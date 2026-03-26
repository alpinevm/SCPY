#![cfg(feature = "ssr")]

mod support;

use std::{
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{FromRef, Path, State},
    http::{header, HeaderValue, StatusCode},
    response::Html,
    routing::get,
};
use reqwest::Client;
use scpy_crypto::{create_room, encrypt_clipboard, KdfParams};
use secopy::{
    api::{api_router, AppState, UpdateClipboardRequest, UpdateClipboardResponse},
    auth::OpaqueLoginFinishRequest,
};
use support::{
    authenticate_clipboard, cookie_client, create_clipboard, login_finish_request,
    start_authenticate_clipboard,
};
use tempfile::TempDir;
use tokio::sync::RwLock;

#[derive(Clone)]
struct BrowserProbeState {
    api: AppState,
    session_cookie: Arc<RwLock<Option<String>>>,
}

impl FromRef<BrowserProbeState> for AppState {
    fn from_ref(input: &BrowserProbeState) -> Self {
        input.api.clone()
    }
}

fn chromium_path() -> String {
    std::env::var("CHROME_BIN").unwrap_or_else(|_| "/snap/bin/chromium".to_string())
}

async fn spawn_probe_server(state: BrowserProbeState) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let base_url = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("listener address must resolve")
    );

    let app = api_router::<BrowserProbeState>()
        .route("/__test__/sse-probe/{room_id}", get(sse_probe_page))
        .with_state(state);

    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("probe server must run");
    });

    (base_url, server)
}

async fn sse_probe_page(
    State(state): State<BrowserProbeState>,
    Path(room_id): Path<String>,
) -> Result<(axum::http::HeaderMap, Html<String>), StatusCode> {
    let Some(set_cookie) = state.session_cookie.read().await.clone() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <body>
    <main id="status">boot</main>
    <script>
      const status = document.getElementById("status");
      fetch("/api/rooms/{room_id}", {{ credentials: "same-origin" }})
        .then((response) => {{
          if (!response.ok) {{
            status.textContent = "snapshot-error:" + response.status;
            return;
          }}
          const events = new EventSource("/api/rooms/{room_id}/events");
          events.onopen = () => {{
            status.textContent = "ready";
          }};
          events.addEventListener("clipboard", (event) => {{
            status.textContent = "pass:" + event.data;
            events.close();
          }});
          events.onerror = () => {{
            if (!status.textContent.startsWith("pass:")) {{
              status.textContent = "error";
            }}
          }};
        }})
        .catch((error) => {{
          status.textContent = "fetch-error:" + String(error);
        }});
    </script>
  </body>
</html>"#,
    );

    Ok((headers, Html(html)))
}

async fn wait_for_server(base_url: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(response) = reqwest::get(format!("{base_url}/api/healthz")).await {
            if response.status() == StatusCode::OK {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for server at {base_url}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn spawn_probe_browser(probe_url: &str, profile_dir: &TempDir) -> std::process::Child {
    Command::new(chromium_path())
        .args([
            "--headless",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--dump-dom",
            "--virtual-time-budget=12000",
            &format!("--user-data-dir={}", profile_dir.path().display()),
        ])
        .arg(probe_url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("chromium must spawn")
}

#[tokio::test]
async fn browser_receives_cookie_authenticated_sse_updates() {
    let probe_state = BrowserProbeState {
        api: AppState::memory(Duration::from_secs(60)),
        session_cookie: Arc::new(RwLock::new(None)),
    };
    let (base_url, server) = spawn_probe_server(probe_state.clone()).await;
    wait_for_server(&base_url, Duration::from_secs(10)).await;

    let create_client = Client::builder().build().expect("plain client must build");
    let password = "browser-password";
    let created = create_room(password, "browser alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&create_client, &base_url, password, &created).await;

    let (login_start, login_start_response) =
        start_authenticate_clipboard(&create_client, &base_url, &room_id, password).await;
    let finish_request: OpaqueLoginFinishRequest =
        login_finish_request(password, login_start, login_start_response);
    let finish_response = create_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request)
        .send()
        .await
        .expect("login finish must resolve");
    assert_eq!(finish_response.status(), StatusCode::OK);
    let session_cookie = finish_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("login finish must set a session cookie")
        .to_str()
        .expect("session cookie must be valid utf-8")
        .to_string();
    *probe_state.session_cookie.write().await = Some(session_cookie);

    let probe_url = format!("{base_url}/__test__/sse-probe/{room_id}");
    let browser_profile = TempDir::new().expect("browser profile dir must create");
    let browser = spawn_probe_browser(&probe_url, &browser_profile);

    tokio::time::sleep(Duration::from_secs(2)).await;

    let updater_client = cookie_client();
    authenticate_clipboard(&updater_client, &base_url, &room_id, password).await;
    let updated_envelope = encrypt_clipboard(
        &created.room_key,
        "browser beta",
        created.envelope.version + 1,
    )
    .expect("updated ciphertext must encrypt");
    let update_response = updater_client
        .post(format!("{base_url}/api/rooms/{room_id}/clipboard"))
        .json(&UpdateClipboardRequest {
            envelope: updated_envelope,
        })
        .send()
        .await
        .expect("update request must resolve");
    assert_eq!(update_response.status(), StatusCode::OK);
    let UpdateClipboardResponse {
        room_id: updated_room_id,
        version,
    } = update_response
        .json()
        .await
        .expect("update response must deserialize");
    assert_eq!(updated_room_id, room_id);
    assert_eq!(version, created.envelope.version + 1);

    let browser_output = browser
        .wait_with_output()
        .expect("chromium process must exit cleanly");
    assert!(
        browser_output.status.success(),
        "chromium exited unsuccessfully\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&browser_output.stdout),
        String::from_utf8_lossy(&browser_output.stderr)
    );

    let dom = String::from_utf8(browser_output.stdout).expect("dom output must be utf-8");
    assert!(
        dom.contains("pass:{&quot;room_id&quot;:&quot;") || dom.contains("pass:{\"room_id\":\""),
        "browser DOM should contain the SSE payload:\n{dom}"
    );
    assert!(
        dom.contains(&room_id),
        "browser DOM should contain the target room id:\n{dom}"
    );

    server.abort();
}
