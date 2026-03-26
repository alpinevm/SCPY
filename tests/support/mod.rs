#![allow(dead_code)]

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    process::Command,
    time::Duration,
};

use futures_util::StreamExt;
use leptos::{config::LeptosOptions, prelude::get_configuration};
use opaque_ke::{ClientLoginFinishParameters, ClientRegistrationFinishParameters};
use rand::rngs::OsRng;
use redis::aio::MultiplexedConnection;
use reqwest::{Client, Response, StatusCode};
use scpy_crypto::CreatedRoom;
use secopy::{
    api::{api_router, AppState},
    auth::{
        OpaqueClientLogin, OpaqueClientLoginStart, OpaqueClientRegistration,
        OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
        OpaqueRegistrationStartRequest,
    },
    protocol::{CreateRoomRequest, CreateRoomResponse},
    server::build_router_with_state,
};
use tokio::task::JoinHandle;

pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    handle: JoinHandle<()>,
}

impl TestServer {
    pub fn abort(self) {
        self.handle.abort();
    }
}

pub async fn spawn_api_test_server(state: AppState) -> TestServer {
    spawn_api_test_server_at(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        state,
    )
    .await
}

pub async fn spawn_api_test_server_at(addr: SocketAddr, state: AppState) -> TestServer {
    let listener = bind_listener(addr).await;
    let addr = listener.local_addr().expect("address must resolve");
    let base_url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, api_router::<AppState>().with_state(state))
            .await
            .expect("test server must run");
    });
    TestServer {
        addr,
        base_url,
        handle,
    }
}

pub async fn spawn_full_app_test_server(state: AppState) -> TestServer {
    spawn_full_app_test_server_at(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        state,
    )
    .await
}

pub async fn spawn_full_app_test_server_at(addr: SocketAddr, state: AppState) -> TestServer {
    spawn_full_app_test_server_at_with_options(addr, leptos_options_for_addr(addr), state).await
}

pub async fn spawn_full_app_test_server_at_with_options(
    addr: SocketAddr,
    leptos_options: LeptosOptions,
    state: AppState,
) -> TestServer {
    let listener = bind_listener(addr).await;
    let addr = listener.local_addr().expect("address must resolve");
    let base_url = format!("http://{addr}");
    let app = build_router_with_state(leptos_options, state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("test server must run");
    });
    TestServer {
        addr,
        base_url,
        handle,
    }
}

pub fn leptos_options_for_addr(addr: SocketAddr) -> LeptosOptions {
    let configuration = get_configuration(Some("Cargo.toml"))
        .or_else(|_| get_configuration(None))
        .expect("leptos configuration must load");
    let mut leptos_options = configuration.leptos_options;
    leptos_options.site_addr = addr;
    leptos_options
}

async fn bind_listener(addr: SocketAddr) -> tokio::net::TcpListener {
    let mut last_error = None;
    for _ in 0..40 {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => return listener,
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    panic!(
        "listener must bind: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown bind error".to_string())
    );
}

pub struct RedisTestInstance {
    container_id: String,
}

impl RedisTestInstance {
    pub async fn start() -> Self {
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "-P",
                "redis:7-alpine",
                "redis-server",
                "--save",
                "",
                "--appendonly",
                "yes",
                "--appendfsync",
                "everysec",
            ])
            .output()
            .expect("docker must be installed");
        assert!(
            output.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let container_id = String::from_utf8(output.stdout)
            .expect("container id must be utf-8")
            .trim()
            .to_string();
        let instance = Self { container_id };
        instance.wait_until_ready().await;
        instance
    }

    pub async fn restart(&self) {
        let output = Command::new("docker")
            .args(["restart", &self.container_id])
            .output()
            .expect("docker restart must run");
        assert!(
            output.status.success(),
            "docker restart failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.wait_until_ready().await;
    }

    pub async fn stop(&self) {
        let output = Command::new("docker")
            .args(["stop", &self.container_id])
            .output()
            .expect("docker stop must run");
        assert!(
            output.status.success(),
            "docker stop failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub async fn start_existing(&self) {
        let output = Command::new("docker")
            .args(["start", &self.container_id])
            .output()
            .expect("docker start must run");
        assert!(
            output.status.success(),
            "docker start failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.wait_until_ready().await;
    }

    pub fn redis_url(&self) -> String {
        let port_output = Command::new("docker")
            .args(["port", &self.container_id, "6379/tcp"])
            .output()
            .expect("docker port must run");
        assert!(
            port_output.status.success(),
            "docker port failed: {}",
            String::from_utf8_lossy(&port_output.stderr)
        );
        let port_line = String::from_utf8(port_output.stdout)
            .expect("port output must be utf-8")
            .lines()
            .next()
            .expect("docker port must return a mapped port")
            .to_string();
        let port = port_line
            .rsplit(':')
            .next()
            .expect("mapped port must contain ':'")
            .trim()
            .parse::<u16>()
            .expect("mapped port must parse");
        format!("redis://127.0.0.1:{port}/")
    }

    pub async fn connection(&self) -> MultiplexedConnection {
        let client = redis::Client::open(self.redis_url()).expect("redis url must parse");
        client
            .get_multiplexed_async_connection()
            .await
            .expect("redis connection must open")
    }

    pub async fn seed_allocator(&self, tiers: &[(u8, Vec<(u64, u64)>)]) {
        let mut connection = self.connection().await;
        redis::cmd("FLUSHDB")
            .query_async::<()>(&mut connection)
            .await
            .expect("flushdb must succeed");
        redis::cmd("SET")
            .arg("scpy:alloc:init:v1")
            .arg("1")
            .query_async::<()>(&mut connection)
            .await
            .expect("allocator sentinel must store");

        for code_len in [3_u8, 4, 5, 6] {
            let starts_key = format!("scpy:alloc:{code_len}:starts");
            let ends_key = format!("scpy:alloc:{code_len}:ends");
            redis::cmd("DEL")
                .arg(&starts_key)
                .arg(&ends_key)
                .query_async::<()>(&mut connection)
                .await
                .expect("interval keys must reset");

            if let Some((_, intervals)) = tiers.iter().find(|(tier, _)| *tier == code_len) {
                for (start, end) in intervals {
                    redis::cmd("ZADD")
                        .arg(&starts_key)
                        .arg(*start)
                        .arg(start.to_string())
                        .query_async::<()>(&mut connection)
                        .await
                        .expect("interval start must store");
                    redis::cmd("HSET")
                        .arg(&ends_key)
                        .arg(start.to_string())
                        .arg(end.to_string())
                        .query_async::<()>(&mut connection)
                        .await
                        .expect("interval end must store");
                }
            }
        }
    }

    pub async fn expiring_members(&self) -> Vec<String> {
        let mut connection = self.connection().await;
        redis::cmd("ZRANGE")
            .arg("scpy:clip:expiring")
            .arg(0)
            .arg(-1)
            .query_async::<Vec<String>>(&mut connection)
            .await
            .expect("expiring members must read")
    }

    pub async fn expiring_score(&self, member: &str) -> Option<u64> {
        let mut connection = self.connection().await;
        redis::cmd("ZSCORE")
            .arg("scpy:clip:expiring")
            .arg(member)
            .query_async::<Option<String>>(&mut connection)
            .await
            .expect("expiring score must read")
            .map(|score| score.parse::<u64>().expect("score must parse"))
    }

    async fn wait_until_ready(&self) {
        for _ in 0..40 {
            if let Ok(mut connection) = redis::Client::open(self.redis_url())
                .expect("redis url must parse")
                .get_multiplexed_async_connection()
                .await
            {
                if redis::cmd("PING")
                    .query_async::<String>(&mut connection)
                    .await
                    .is_ok()
                {
                    return;
                }
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        panic!("redis container did not become ready in time");
    }
}

impl Drop for RedisTestInstance {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output();
    }
}

pub struct SseStream {
    stream: futures_util::stream::BoxStream<'static, Result<bytes::Bytes, reqwest::Error>>,
    buffer: String,
}

pub fn cookie_client() -> Client {
    Client::builder()
        .cookie_store(true)
        .build()
        .expect("cookie client must build")
}

pub async fn create_clipboard(
    client: &Client,
    base_url: &str,
    password: &str,
    created: &CreatedRoom,
) -> String {
    let mut rng = OsRng;
    let registration_start =
        OpaqueClientRegistration::start(&mut rng, password.as_bytes()).expect("must start");
    let registration_response = client
        .post(format!("{base_url}/api/auth/register/start"))
        .json(&OpaqueRegistrationStartRequest {
            message: registration_start.message.clone(),
        })
        .send()
        .await
        .expect("registration start must succeed");
    assert_eq!(registration_response.status(), StatusCode::OK);
    let registration_response = registration_response
        .json::<secopy::auth::OpaqueRegistrationStartResponse>()
        .await
        .expect("registration response must deserialize");
    let registration_finish = registration_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            registration_response.message,
            ClientRegistrationFinishParameters::default(),
        )
        .expect("registration must finish");

    let create_response = client
        .post(format!("{base_url}/api/rooms"))
        .json(&CreateRoomRequest {
            auth: secopy::auth::OpaqueRoomRegistration {
                credential_id: registration_response.credential_id,
                registration_upload: registration_finish.message,
            },
            meta: created.meta.clone(),
            envelope: created.envelope.clone(),
        })
        .send()
        .await
        .expect("create room request must succeed");
    assert_eq!(create_response.status(), StatusCode::CREATED);
    create_response
        .json::<CreateRoomResponse>()
        .await
        .expect("create room response must deserialize")
        .room_id
}

pub async fn authenticate_clipboard(
    client: &Client,
    base_url: &str,
    room_id: &str,
    password: &str,
) {
    let (login_start, login_start_response) =
        start_authenticate_clipboard(client, base_url, room_id, password).await;
    let login_finish_response = finish_authenticate_clipboard(
        client,
        base_url,
        password,
        login_start,
        login_start_response,
    )
    .await;
    assert_eq!(login_finish_response.status(), StatusCode::OK);
}

pub async fn start_authenticate_clipboard(
    client: &Client,
    base_url: &str,
    room_id: &str,
    password: &str,
) -> (OpaqueClientLoginStart, OpaqueLoginStartResponse) {
    let mut rng = OsRng;
    let login_start =
        OpaqueClientLogin::start(&mut rng, password.as_bytes()).expect("login must start");
    let login_start_response = client
        .post(format!("{base_url}/api/auth/login/start"))
        .json(&OpaqueLoginStartRequest {
            room_id: room_id.to_string(),
            message: login_start.message.clone(),
        })
        .send()
        .await
        .expect("login start must succeed");
    if login_start_response.status() != StatusCode::OK {
        let status = login_start_response.status();
        let body = login_start_response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        panic!("login start failed: status={status}, body={body}");
    }
    (
        login_start,
        login_start_response
            .json::<secopy::auth::OpaqueLoginStartResponse>()
            .await
            .expect("login start response must deserialize"),
    )
}

pub async fn finish_authenticate_clipboard(
    client: &Client,
    base_url: &str,
    password: &str,
    login_start: OpaqueClientLoginStart,
    login_start_response: OpaqueLoginStartResponse,
) -> Response {
    let request = login_finish_request(password, login_start, login_start_response);
    client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&request)
        .send()
        .await
        .expect("login finish must succeed")
}

pub fn login_finish_request(
    password: &str,
    login_start: OpaqueClientLoginStart,
    login_start_response: OpaqueLoginStartResponse,
) -> OpaqueLoginFinishRequest {
    let mut rng = OsRng;
    let login_finish = login_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            login_start_response.message,
            ClientLoginFinishParameters::default(),
        )
        .expect("login must finish");
    OpaqueLoginFinishRequest {
        login_session_id: login_start_response.login_session_id,
        message: login_finish.message,
    }
}

impl SseStream {
    pub fn new(response: Response) -> Self {
        Self {
            stream: response.bytes_stream().boxed(),
            buffer: String::new(),
        }
    }

    pub async fn next_event<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, String> {
        loop {
            if let Some(event) = extract_event(&mut self.buffer)? {
                return Ok(event);
            }

            let next_chunk = self
                .stream
                .next()
                .await
                .ok_or_else(|| "sse stream closed before an event arrived".to_string())?
                .map_err(|error| error.to_string())?;

            self.buffer
                .push_str(std::str::from_utf8(&next_chunk).map_err(|error| error.to_string())?);
        }
    }
}

fn extract_event<T: serde::de::DeserializeOwned>(buffer: &mut String) -> Result<Option<T>, String> {
    let normalized = buffer.replace("\r\n", "\n");
    if let Some(separator) = normalized.find("\n\n") {
        let event_block = normalized[..separator].to_string();
        *buffer = normalized[separator + 2..].to_string();

        let mut data_lines = Vec::new();
        for line in event_block.lines() {
            if let Some(data) = line.strip_prefix("data:") {
                data_lines.push(data.trim_start());
            }
        }

        if data_lines.is_empty() {
            return Ok(None);
        }

        let payload = data_lines.join("\n");
        let event = serde_json::from_str::<T>(&payload).map_err(|error| error.to_string())?;
        Ok(Some(event))
    } else {
        Ok(None)
    }
}
