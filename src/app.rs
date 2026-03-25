use std::{cell::RefCell, rc::Rc};

use leptos::html::Input;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::{
    components::{Route, Router, Routes},
    hooks::{use_navigate, use_params_map},
    NavigateOptions, ParamSegment, StaticSegment,
};
use scpy_crypto::{
    cipher_suite_label, create_room as create_encrypted_room, decrypt_clipboard, encrypt_clipboard,
    unlock_room_key, KdfParams, RoomKey,
};

#[cfg(target_arch = "wasm32")]
use crate::protocol::ClipboardEvent;
use crate::protocol::{
    CreateRoomRequest, CreateRoomResponse, GetRoomResponse, UpdateClipboardRequest,
    UpdateClipboardResponse,
};

#[cfg(target_arch = "wasm32")]
use gloo_net::http::Request;
#[cfg(target_arch = "wasm32")]
use js_sys::{Function, Reflect};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{Event, EventSource, MessageEvent};

#[cfg(target_arch = "wasm32")]
struct RoomEventStream {
    event_source: EventSource,
    _on_clipboard: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

#[cfg(not(target_arch = "wasm32"))]
struct RoomEventStream;

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <link id="leptos" rel="stylesheet" href="/pkg/scpy-app.css"/>
                <meta
                    name="description"
                    content="scpy.app is an end-to-end encrypted live clipboard with short links and live updates."
                />
                <title>"scpy.app | End-to-end encrypted live clipboard"</title>
            </head>
            <body class="app-body">
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    AppBody()
}

#[component]
pub fn AppBody() -> impl IntoView {
    view! {
        <main class="page-shell">
            <Router>
                <Routes fallback=|| view! { <NotFoundPage/> }>
                    <Route path=StaticSegment("") view=LandingPage/>
                    <Route path=(StaticSegment("c"), ParamSegment("room_id")) view=RoomPage/>
                </Routes>
            </Router>
        </main>
    }
}

#[component]
fn BrandWord() -> impl IntoView {
    view! {
        <h2 class="brand-name">
            <span class="brand-emphasis">"S"</span>
            <span class="brand-muted">"ecure "</span>
            <span class="brand-emphasis">"C"</span>
            <span class="brand-muted">"o"</span>
            <span class="brand-emphasis">"P"</span>
            <span class="brand-emphasis">"Y"</span>
        </h2>
    }
}

#[component]
fn LandingPage() -> impl IntoView {
    let create_password = RwSignal::new(String::new());
    let create_clipboard = RwSignal::new(String::new());
    let create_pending = RwSignal::new(false);
    let create_status = RwSignal::new(String::from(
        "Create an encrypted clipboard in the browser. Only encrypted metadata and ciphertext are sent to the backend.",
    ));
    let navigate = use_navigate();

    let create_room = move |_| {
        let password = create_password.get();
        let clipboard = create_clipboard.get();
        let navigate = navigate.clone();

        if password.trim().is_empty() {
            create_status.set("Enter a password before creating a clipboard.".to_string());
            return;
        }

        create_pending.set(true);
        create_status.set("Encrypting locally and uploading ciphertext…".to_string());

        spawn_local(async move {
            let result =
                match create_encrypted_room(&password, &clipboard, KdfParams::interactive()) {
                    Ok(created) => {
                        create_remote_room(&CreateRoomRequest {
                            meta: created.meta,
                            envelope: created.envelope,
                        })
                        .await
                    }
                    Err(error) => Err(error.to_string()),
                };

            match result {
                Ok(CreateRoomResponse { room_id }) => {
                    create_status.set("Clipboard created. Opening it now…".to_string());
                    navigate(&room_href(&room_id), NavigateOptions::default());
                }
                Err(error) => {
                    create_status.set(format!("Clipboard creation failed: {error}"));
                }
            }

            create_pending.set(false);
        });
    };

    view! {
        <div class="landing-shell">
            <header class="topbar">
                <div class="brand-lockup">
                    <BrandWord/>
                </div>
            </header>

            <section class="create-panel card">
                <div class="panel-head">
                    <div>
                        <p class="eyebrow">"Create"</p>
                        <h2 class="brand-name create-title">"Spin up an encrypted clipboard now."</h2>
                    </div>
                    <div class="status-pill">
                        <span>
                            {move || {
                                if create_pending.get() {
                                    "creating"
                                } else {
                                    "idle"
                                }
                            }}
                        </span>
                    </div>
                </div>

                <div class="create-grid">
                    <label class="field">
                        <span class="field-label">"Password"</span>
                        <input
                            class="text-input"
                            type="password"
                            placeholder="password never leaves this browser"
                            prop:value=move || create_password.get()
                            on:input=move |ev| create_password.set(event_target_value(&ev))
                        />
                    </label>

                    <label class="field field-area">
                        <span class="field-label">"Starting text"</span>
                        <textarea
                            class="text-area text-area-compact"
                            rows="8"
                            placeholder="Paste or type text here."
                            prop:value=move || create_clipboard.get()
                            on:input=move |ev| create_clipboard.set(event_target_value(&ev))
                        ></textarea>
                    </label>
                </div>

                <div class="button-row">
                    <button
                        class="button button-primary"
                        disabled=move || create_pending.get()
                        on:click=create_room
                    >
                        <span>
                            {move || {
                                if create_pending.get() {
                                    "Creating clipboard…"
                                } else {
                                    "Create encrypted clipboard"
                                }
                            }}
                        </span>
                    </button>
                </div>

                <p class="room-copy">
                    <span>{move || create_status.get()}</span>
                </p>
            </section>

            <section class="hero-copy card">
                <p class="eyebrow">"Fast and simple"</p>
                <h1 class="hero-stack">
                    <span class="hero-stack-line">"Private text"</span>
                    <span class="hero-stack-line">"Live sync"</span>
                    <span class="hero-stack-line">"Short links"</span>
                </h1>
                <p class="lead">
                    "Set a password, share a short link, and keep typing. Anyone with both can unlock"
                    " the clipboard and see the latest text."
                </p>
                <p class="security-copy">
                    {format!("scpy.app runs {} in the browser so the server only handles encrypted data.", cipher_suite_label())}
                </p>
            </section>
        </div>
    }
}

#[component]
fn RoomPage() -> impl IntoView {
    let params = use_params_map();
    let room_id = move || {
        params.with(|params| {
            params
                .get("room_id")
                .unwrap_or_else(|| "unknown-clipboard".to_string())
        })
    };

    let password = RwSignal::new(String::new());
    let clipboard = RwSignal::new(String::new());
    let room_key = RwSignal::new(None::<RoomKey>);
    let unlocked = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let version = RwSignal::new(0_u64);
    let status = RwSignal::new(String::from(
        "Unlock the clipboard to fetch the encrypted snapshot and begin live updates.",
    ));
    let share_copied = RwSignal::new(false);
    let share_input_ref = NodeRef::<Input>::new();
    let stream_slot: Rc<RefCell<Option<RoomEventStream>>> = Rc::new(RefCell::new(None));

    let unlock_room = move |_| {
        let room_id_value = room_id();
        let password_value = password.get();
        let stream_slot = stream_slot.clone();

        if password_value.trim().is_empty() {
            unlocked.set(false);
            room_key.set(None);
            close_room_stream(&stream_slot);
            status.set("Enter the password to unlock the clipboard.".to_string());
            return;
        }

        loading.set(true);
        status.set("Fetching ciphertext and decrypting locally…".to_string());

        spawn_local(async move {
            let result = fetch_room_snapshot(&room_id_value)
                .await
                .and_then(|snapshot| {
                    unlock_room_key(&password_value, &snapshot.meta)
                        .and_then(|key| {
                            let plaintext = decrypt_clipboard(&key, &snapshot.envelope)?;
                            Ok((key, plaintext, snapshot.envelope.version))
                        })
                        .map_err(|error| error.to_string())
                });

            match result {
                Ok((key, plaintext, next_version)) => {
                    clipboard.set(plaintext);
                    version.set(next_version);
                    room_key.set(Some(key.clone()));
                    unlocked.set(true);
                    status.set(format!(
                        "Clipboard unlocked with {}. Listening for live encrypted updates.",
                        cipher_suite_label()
                    ));
                    attach_room_stream(
                        &room_id_value,
                        key,
                        clipboard,
                        version,
                        status,
                        stream_slot,
                    );
                }
                Err(error) => {
                    close_room_stream(&stream_slot);
                    room_key.set(None);
                    unlocked.set(false);
                    status.set(format!("Unlock failed: {error}"));
                }
            }

            loading.set(false);
        });
    };

    let save_update = move |_| {
        let room_id_value = room_id();
        let maybe_key = room_key.get();
        let plaintext = clipboard.get();

        let Some(key) = maybe_key else {
            status.set("Unlock the clipboard before sending an encrypted update.".to_string());
            return;
        };

        saving.set(true);
        status.set(
            "Encrypting the updated clipboard and sending ciphertext to the server…".to_string(),
        );

        spawn_local(async move {
            let next_version = version.get().saturating_add(1);
            let result = match encrypt_clipboard(&key, &plaintext, next_version) {
                Ok(envelope) => {
                    post_clipboard_update(&room_id_value, &UpdateClipboardRequest { envelope })
                        .await
                }
                Err(error) => Err(error.to_string()),
            };

            match result {
                Ok(UpdateClipboardResponse {
                    version: next_version,
                    ..
                }) => {
                    version.set(next_version);
                    status.set(format!("Encrypted update sent at version {next_version}."));
                }
                Err(error) => {
                    status.set(format!("Update failed: {error}"));
                }
            }

            saving.set(false);
        });
    };

    let room_link = move || absolute_room_href(&room_id());
    let copy_room_link = move |_| {
        let link = absolute_room_href(&room_id());
        let share_input_ref = share_input_ref;

        spawn_local(async move {
            match copy_text_to_clipboard(&link, share_input_ref).await {
                Ok(()) => share_copied.set(true),
                Err(error) => {
                    share_copied.set(false);
                    status.set(format!("Could not copy the share link: {error}"));
                }
            }
        });
    };

    view! {
        <div class="room-shell">
            <header class="topbar room-topbar">
                <div class="brand-lockup">
                    <BrandWord/>
                </div>

                <a class="button button-secondary" href="/">
                    "Back home"
                </a>
            </header>

            <section class="room-grid">
                <div class="room-main card">
                    <div class="share-card room-share-card">
                        <p class="field-label">"Share link"</p>
                        <div class="share-row">
                            <input
                                class="text-input share-link-input"
                                readonly=true
                                node_ref=share_input_ref
                                prop:value=room_link
                                on:click=copy_room_link.clone()
                            />
                            <button
                                class="copy-link-button"
                                type="button"
                                on:click=copy_room_link
                            >
                                <svg viewBox="0 0 24 24" aria-hidden="true">
                                    <rect x="9" y="9" width="10" height="10" rx="2"></rect>
                                    <path d="M7 15H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                <span>{move || if share_copied.get() { "Copied" } else { "Copy" }}</span>
                            </button>
                        </div>
                    </div>

                    <div class="field-grid">
                        <label class="field">
                            <span class="field-label">"Password"</span>
                            <input
                                class="text-input"
                                type="password"
                                placeholder="password stays local to this browser"
                                prop:value=move || password.get()
                                on:input=move |ev| password.set(event_target_value(&ev))
                            />
                        </label>

                        <button
                            class="button button-primary"
                            disabled=move || loading.get()
                            on:click=unlock_room.clone()
                        >
                            {move || {
                                if loading.get() {
                                    "Unlocking…"
                                } else if unlocked.get() {
                                    "Reload clipboard"
                                } else {
                                    "Unlock clipboard"
                                }
                            }}
                        </button>
                    </div>

                    <p class="room-copy">{move || status.get()}</p>

                    <label class="field field-area">
                        <span class="field-label">"Clipboard payload"</span>
                        <textarea
                            class="text-area"
                            rows="12"
                            prop:value=move || clipboard.get()
                            on:input=move |ev| clipboard.set(event_target_value(&ev))
                        ></textarea>
                    </label>

                    <div class="button-row">
                        <button
                            class="button button-secondary"
                            disabled=move || !unlocked.get() || saving.get()
                            on:click=save_update
                        >
                            {move || if saving.get() { "Sending…" } else { "Encrypt and send" }}
                        </button>
                    </div>
                </div>
            </section>
        </div>
    }
}

#[component]
fn NotFoundPage() -> impl IntoView {
    view! {
        <section class="not-found card">
            <p class="eyebrow">"404"</p>
            <h1>"This clipboard does not exist."</h1>
            <p class="lead">
                "The link may be wrong, or the clipboard may have expired."
            </p>
            <a class="button button-primary" href="/">
                "Return home"
            </a>
        </section>
    }
}

fn room_href(room_id: &str) -> String {
    format!("/c/{room_id}")
}

fn absolute_room_href(room_id: &str) -> String {
    let room_path = room_href(room_id);

    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        if let Ok(origin) = window.location().origin() {
            return format!("{origin}{room_path}");
        }
    }

    room_path
}

async fn copy_text_to_clipboard(text: &str, input_ref: NodeRef<Input>) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(window) = web_sys::window() else {
            return Err("window is unavailable".to_string());
        };

        if JsFuture::from(window.navigator().clipboard().write_text(text))
            .await
            .is_ok()
        {
            return Ok(());
        }

        let Some(document) = window.document() else {
            return Err("document is unavailable".to_string());
        };
        let Some(input) = input_ref.get() else {
            return Err("share link input is unavailable".to_string());
        };

        input.select();

        let exec_command = Reflect::get(document.as_ref(), &JsValue::from_str("execCommand"))
            .map_err(|error| js_error(&error))?;
        let exec_command = exec_command
            .dyn_into::<Function>()
            .map_err(|error| js_error(&error))?;

        return match exec_command.call1(document.as_ref(), &JsValue::from_str("copy")) {
            Ok(result) if result.as_bool() == Some(true) => Ok(()),
            Ok(_) => Err("the browser rejected the copy command".to_string()),
            Err(error) => Err(js_error(&error)),
        };
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (text, input_ref);
        Err("clipboard copy requires browser hydration".to_string())
    }
}

fn close_room_stream(stream_slot: &Rc<RefCell<Option<RoomEventStream>>>) {
    #[cfg(target_arch = "wasm32")]
    if let Some(stream) = stream_slot.borrow_mut().take() {
        stream.event_source.close();
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = stream_slot;
}

fn attach_room_stream(
    room_id: &str,
    room_key: RoomKey,
    clipboard: RwSignal<String>,
    version: RwSignal<u64>,
    status: RwSignal<String>,
    stream_slot: Rc<RefCell<Option<RoomEventStream>>>,
) {
    close_room_stream(&stream_slot);

    #[cfg(target_arch = "wasm32")]
    {
        let event_source = match EventSource::new(&format!("/api/rooms/{room_id}/events")) {
            Ok(event_source) => event_source,
            Err(error) => {
                status.set(format!(
                    "Clipboard unlocked, but the live SSE connection failed: {}",
                    js_error(&error)
                ));
                return;
            }
        };

        let event_room_key = room_key.clone();
        let on_clipboard =
            Closure::<dyn FnMut(MessageEvent)>::wrap(Box::new(move |event: MessageEvent| {
                let Some(payload) = event.data().as_string() else {
                    status.set("Received a non-text SSE payload.".to_string());
                    return;
                };

                match serde_json::from_str::<ClipboardEvent>(&payload)
                    .map_err(|error| error.to_string())
                    .and_then(|clipboard_event| {
                        let decrypted =
                            decrypt_clipboard(&event_room_key, &clipboard_event.envelope)
                                .map_err(|error| error.to_string())?;
                        Ok((decrypted, clipboard_event.envelope.version))
                    }) {
                    Ok((decrypted, next_version)) => {
                        clipboard.set(decrypted);
                        version.set(next_version);
                        status.set(format!("Live update received at version {next_version}."));
                    }
                    Err(error) => {
                        status.set(format!("Live update failed to decrypt: {error}"));
                    }
                }
            }));

        if let Err(error) = event_source
            .add_event_listener_with_callback("clipboard", on_clipboard.as_ref().unchecked_ref())
        {
            status.set(format!(
                "Clipboard unlocked, but the SSE listener setup failed: {}",
                js_error(&error)
            ));
            event_source.close();
            return;
        }

        let on_error = Closure::<dyn FnMut(Event)>::wrap(Box::new(move |_| {
            status
                .set("Live connection dropped. Unlock the clipboard again to resync.".to_string());
        }));
        let _ = event_source
            .add_event_listener_with_callback("error", on_error.as_ref().unchecked_ref());

        *stream_slot.borrow_mut() = Some(RoomEventStream {
            event_source,
            _on_clipboard: on_clipboard,
            _on_error: on_error,
        });

        status.update(|message| {
            message.push_str(" SSE connected.");
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = (room_id, room_key, clipboard, version, status, stream_slot);
}

#[cfg(target_arch = "wasm32")]
async fn create_remote_room(request: &CreateRoomRequest) -> Result<CreateRoomResponse, String> {
    let response = Request::post("/api/rooms")
        .json(request)
        .map_err(|error| error.to_string())?
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if !response.ok() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "server returned {status} while creating the clipboard: {body}"
        ));
    }

    response
        .json::<CreateRoomResponse>()
        .await
        .map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn create_remote_room(_request: &CreateRoomRequest) -> Result<CreateRoomResponse, String> {
    Err("Clipboard creation requires browser hydration.".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_room_snapshot(room_id: &str) -> Result<GetRoomResponse, String> {
    let response = Request::get(&format!("/api/rooms/{room_id}"))
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if !response.ok() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "server returned {status} while loading the clipboard: {body}"
        ));
    }

    response
        .json::<GetRoomResponse>()
        .await
        .map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_room_snapshot(_room_id: &str) -> Result<GetRoomResponse, String> {
    Err("Clipboard loading requires browser hydration.".to_string())
}

#[cfg(target_arch = "wasm32")]
async fn post_clipboard_update(
    room_id: &str,
    request: &UpdateClipboardRequest,
) -> Result<UpdateClipboardResponse, String> {
    let response = Request::post(&format!("/api/rooms/{room_id}/clipboard"))
        .json(request)
        .map_err(|error| error.to_string())?
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if !response.ok() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "server returned {status} while saving the update: {body}"
        ));
    }

    response
        .json::<UpdateClipboardResponse>()
        .await
        .map_err(|error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn post_clipboard_update(
    _room_id: &str,
    _request: &UpdateClipboardRequest,
) -> Result<UpdateClipboardResponse, String> {
    Err("Clipboard updates require browser hydration.".to_string())
}

#[cfg(target_arch = "wasm32")]
fn js_error(value: &JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}
