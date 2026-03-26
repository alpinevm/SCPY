use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    extract::{FromRef, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration};
use rand::{rngs::OsRng, RngCore};
use scpy_crypto::CipherEnvelope;
use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

use crate::auth::{
    new_server_setup, OpaqueLoginFinishRequest, OpaqueLoginFinishResponse, OpaqueLoginStartRequest,
    OpaqueLoginStartResponse, OpaqueRegistrationStartRequest, OpaqueRegistrationStartResponse,
    OpaqueServerSetup, StoredOpaqueLoginState, StoredOpaqueRegistration, StoredOpaqueSession,
};
pub use crate::protocol::{
    ClipboardEvent, CreateRoomRequest, CreateRoomResponse, GetRoomResponse, UpdateClipboardRequest,
    UpdateClipboardResponse,
};
use crate::store::{MemoryRoomStore, RedisRoomStore, RoomStore, StoreError, StoredRoom};

const DEFAULT_ROOM_TTL: Duration = Duration::from_secs(60 * 60 * 24);
const DEFAULT_LOGIN_TTL: Duration = Duration::from_secs(60);
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(60 * 30);

#[derive(Clone)]
pub struct AppState {
    inner: Arc<InnerState>,
}

struct InnerState {
    store: Arc<dyn RoomStore>,
    channels: Mutex<HashMap<String, broadcast::Sender<ClipboardEvent>>>,
    opaque_setup: Arc<OpaqueServerSetup>,
    room_ttl: Duration,
    login_ttl: Duration,
    session_ttl: Duration,
}

#[derive(Clone, Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    mode: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ArchitectureResponse {
    brand: &'static str,
    runtime: &'static str,
    server: &'static str,
    frontend: &'static str,
    rendering_model: &'static str,
    sync_transport: &'static str,
    security_model: &'static str,
    seo_mode: &'static str,
}

pub fn api_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: FromRef<S>,
{
    Router::new()
        .route("/api/healthz", get(healthz))
        .route("/api/architecture", get(architecture))
        .route("/api/auth/register/start", post(register_start))
        .route("/api/auth/login/start", post(login_start))
        .route("/api/auth/login/finish", post(login_finish))
        .route("/api/rooms", post(create_room))
        .route("/api/rooms/{room_id}", get(get_room))
        .route("/api/rooms/{room_id}/clipboard", post(update_clipboard))
        .route("/api/rooms/{room_id}/events", get(room_events))
}

impl AppState {
    pub fn new(
        store: Arc<dyn RoomStore>,
        opaque_setup: OpaqueServerSetup,
        room_ttl: Duration,
        login_ttl: Duration,
        session_ttl: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(InnerState {
                store,
                channels: Mutex::new(HashMap::new()),
                opaque_setup: Arc::new(opaque_setup),
                room_ttl,
                login_ttl,
                session_ttl,
            }),
        }
    }

    pub fn memory(room_ttl: Duration) -> Self {
        Self::new(
            Arc::new(MemoryRoomStore::new()),
            new_server_setup(),
            room_ttl,
            DEFAULT_LOGIN_TTL,
            DEFAULT_SESSION_TTL,
        )
    }

    pub async fn redis(redis_url: &str, room_ttl: Duration) -> Result<Self, StoreError> {
        Self::redis_with_reclaimer(redis_url, room_ttl, Duration::from_secs(1), 128).await
    }

    pub async fn redis_with_reclaimer(
        redis_url: &str,
        room_ttl: Duration,
        reclaim_interval: Duration,
        reclaim_batch_limit: usize,
    ) -> Result<Self, StoreError> {
        let store = RedisRoomStore::connect_with_options(redis_url, true).await?;
        let opaque_setup = store.get_or_create_server_setup().await?;
        let state = Self::new(
            Arc::new(store.clone()),
            opaque_setup,
            room_ttl,
            DEFAULT_LOGIN_TTL,
            DEFAULT_SESSION_TTL,
        );
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(reclaim_interval);
            interval.tick().await;
            loop {
                interval.tick().await;
                match store.reclaim_expired(reclaim_batch_limit).await {
                    Ok(result) if result.reclaimed > 0 || result.cleaned > 0 => {
                        tracing::debug!(
                            reclaimed = result.reclaimed,
                            cleaned = result.cleaned,
                            scanned = result.scanned,
                            "reclaimed expired clipboard allocations"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(?error, "failed to reclaim expired clipboard allocations");
                    }
                }
            }
        });
        Ok(state)
    }

    async fn create_room(&self, request: CreateRoomRequest) -> Result<GetRoomResponse, StoreError> {
        let auth = StoredOpaqueRegistration {
            credential_id: request.auth.credential_id,
            password_file: ServerRegistration::finish(request.auth.registration_upload),
        };
        let stored = self
            .inner
            .store
            .create(
                StoredRoom {
                    auth,
                    meta: request.meta,
                    envelope: request.envelope,
                },
                self.inner.room_ttl,
            )
            .await?;

        let _ = self.sender_for(&stored.room_id).await;

        Ok(GetRoomResponse {
            room_id: stored.room_id,
            meta: stored.meta,
            envelope: stored.envelope,
        })
    }

    async fn get_room(&self, room_id: &str) -> Result<Option<GetRoomResponse>, StoreError> {
        let room = match self.inner.store.get(room_id).await? {
            Some(room) => room,
            None => return Ok(None),
        };

        Ok(Some(GetRoomResponse {
            room_id: room_id.to_string(),
            meta: room.meta,
            envelope: room.envelope,
        }))
    }

    async fn start_registration(
        &self,
        request: OpaqueRegistrationStartRequest,
    ) -> Result<OpaqueRegistrationStartResponse, StoreError> {
        let credential_id = random_bytes(16);
        let result = ServerRegistration::start(
            self.inner.opaque_setup.as_ref(),
            request.message,
            &credential_id,
        )
        .map_err(|error| StoreError::Opaque(error.to_string()))?;

        Ok(OpaqueRegistrationStartResponse {
            credential_id,
            message: result.message,
        })
    }

    async fn start_login(
        &self,
        request: OpaqueLoginStartRequest,
    ) -> Result<OpaqueLoginStartResponse, StoreError> {
        let registration = self.inner.store.get_registration(&request.room_id).await?;
        let credential_id = registration
            .as_ref()
            .map(|registration| registration.credential_id.clone())
            .unwrap_or_else(|| request.room_id.as_bytes().to_vec());
        let password_file = registration.map(|registration| registration.password_file);
        let mut rng = OsRng;
        let result = ServerLogin::start(
            &mut rng,
            self.inner.opaque_setup.as_ref(),
            password_file,
            request.message,
            &credential_id,
            ServerLoginParameters::default(),
        )
        .map_err(|error| StoreError::Opaque(error.to_string()))?;

        let login_session_id = random_token(24);
        self.inner
            .store
            .put_login_state(
                &login_session_id,
                StoredOpaqueLoginState {
                    room_id: request.room_id,
                    state: result.state,
                },
                self.inner.login_ttl,
            )
            .await?;

        Ok(OpaqueLoginStartResponse {
            login_session_id,
            message: result.message,
        })
    }

    async fn finish_login(
        &self,
        request: OpaqueLoginFinishRequest,
    ) -> Result<Option<(String, String)>, StoreError> {
        let Some(login_state) = self
            .inner
            .store
            .take_login_state(&request.login_session_id)
            .await?
        else {
            return Ok(None);
        };

        let room_id = login_state.room_id;
        let result = login_state
            .state
            .finish(request.message, ServerLoginParameters::default());
        if result.is_err() {
            return Ok(None);
        }

        let session_id = random_token(32);
        let created_at_ms = now_unix_ms();
        self.inner
            .store
            .put_session(
                &session_id,
                StoredOpaqueSession {
                    room_id: room_id.clone(),
                    created_at_ms,
                    expires_at_ms: created_at_ms
                        .saturating_add(ttl_to_millis(self.inner.session_ttl)),
                },
                self.inner.session_ttl,
            )
            .await?;

        Ok(Some((room_id, session_id)))
    }

    async fn update_room(
        &self,
        room_id: &str,
        envelope: CipherEnvelope,
    ) -> Result<Option<UpdateClipboardResponse>, StoreError> {
        let updated = match self
            .inner
            .store
            .update(room_id, envelope.clone(), self.inner.room_ttl)
            .await?
        {
            Some(room) => room,
            None => return Ok(None),
        };

        let event = ClipboardEvent {
            room_id: room_id.to_string(),
            envelope: envelope.clone(),
        };
        let sender = self.sender_for(room_id).await;
        let _ = sender.send(event);

        Ok(Some(UpdateClipboardResponse {
            room_id: room_id.to_string(),
            version: updated.content_version,
        }))
    }

    async fn subscribe(
        &self,
        room_id: &str,
    ) -> Result<Option<broadcast::Receiver<ClipboardEvent>>, StoreError> {
        if self.inner.store.get(room_id).await?.is_none() {
            return Ok(None);
        }

        let sender = self.sender_for(room_id).await;
        Ok(Some(sender.subscribe()))
    }

    async fn is_authorized(&self, headers: &HeaderMap, room_id: &str) -> Result<bool, StoreError> {
        let Some(session_token) = session_cookie_value(headers, &session_cookie_name(room_id))
        else {
            return Ok(false);
        };
        let Some(session) = self.inner.store.get_session(session_token).await? else {
            return Ok(false);
        };
        Ok(session.room_id == room_id)
    }

    async fn sender_for(&self, room_id: &str) -> broadcast::Sender<ClipboardEvent> {
        let mut channels = self.inner.channels.lock().await;
        channels
            .entry(room_id.to_string())
            .or_insert_with(|| {
                let (sender, _) = broadcast::channel(32);
                sender
            })
            .clone()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::memory(DEFAULT_ROOM_TTL)
    }
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "scpy.app",
        mode: "blind-sse-api",
    })
}

async fn architecture() -> Json<ArchitectureResponse> {
    Json(ArchitectureResponse {
        brand: "scpy.app",
        runtime: "tokio",
        server: "axum",
        frontend: "leptos",
        rendering_model: "ssr-plus-hydrate",
        sync_transport: "server-sent-events",
        security_model: "e2ee-zero-knowledge-v1-plus-opaque",
        seo_mode: "public-ssr-private-noindex",
    })
}

async fn register_start(
    State(state): State<AppState>,
    Json(request): Json<OpaqueRegistrationStartRequest>,
) -> Result<Json<OpaqueRegistrationStartResponse>, StatusCode> {
    state
        .start_registration(request)
        .await
        .map(Json)
        .map_err(store_error_to_status)
}

async fn login_start(
    State(state): State<AppState>,
    Json(request): Json<OpaqueLoginStartRequest>,
) -> Result<Json<OpaqueLoginStartResponse>, StatusCode> {
    state
        .start_login(request)
        .await
        .map(Json)
        .map_err(store_error_to_status)
}

async fn login_finish(
    State(state): State<AppState>,
    Json(request): Json<OpaqueLoginFinishRequest>,
) -> Result<Response, StatusCode> {
    let Some((room_id, session_id)) = state
        .finish_login(request)
        .await
        .map_err(store_error_to_status)?
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let cookie = build_session_cookie(&room_id, &session_id, state.inner.session_ttl)?;
    let mut response = Json(OpaqueLoginFinishResponse {
        authenticated: true,
    })
    .into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

async fn create_room(
    State(state): State<AppState>,
    Json(request): Json<CreateRoomRequest>,
) -> Result<(StatusCode, Json<CreateRoomResponse>), StatusCode> {
    if request.envelope.version == 0 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let room = state
        .create_room(request)
        .await
        .map_err(store_error_to_status)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateRoomResponse {
            room_id: room.room_id,
        }),
    ))
}

async fn get_room(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Json<GetRoomResponse>, StatusCode> {
    if !state
        .is_authorized(&headers, &room_id)
        .await
        .map_err(store_error_to_status)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .get_room(&room_id)
        .await
        .map_err(store_error_to_status)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_clipboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    Json(request): Json<UpdateClipboardRequest>,
) -> Result<Json<UpdateClipboardResponse>, StatusCode> {
    if request.envelope.version == 0 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    if !state
        .is_authorized(&headers, &room_id)
        .await
        .map_err(store_error_to_status)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .update_room(&room_id, request.envelope)
        .await
        .map_err(store_error_to_status)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn room_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(room_id): Path<String>,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !state
        .is_authorized(&headers, &room_id)
        .await
        .map_err(store_error_to_status)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut receiver = state
        .subscribe(&room_id)
        .await
        .map_err(store_error_to_status)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let stream = stream! {
        loop {
            match receiver.recv().await {
                Ok(message) => {
                    let event = Event::default()
                        .event("clipboard")
                        .json_data(message)
                        .expect("clipboard events must serialize");
                    yield Ok(event);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn store_error_to_status(error: StoreError) -> StatusCode {
    match error {
        StoreError::AllocatorExhausted => StatusCode::SERVICE_UNAVAILABLE,
        StoreError::VersionConflict { .. } => StatusCode::CONFLICT,
        StoreError::InvalidRoomId => StatusCode::NOT_FOUND,
        StoreError::Opaque(_) => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn build_session_cookie(
    room_id: &str,
    session_id: &str,
    ttl: Duration,
) -> Result<HeaderValue, StatusCode> {
    let value = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        session_cookie_name(room_id),
        session_id,
        ttl.as_secs()
    );
    HeaderValue::from_str(&value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn session_cookie_name(room_id: &str) -> String {
    format!("scpy_session_{room_id}")
}

fn session_cookie_value<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let mut parts = pair.trim().splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(name), Some(value)) if name == cookie_name => Some(value),
            _ => None,
        }
    })
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_token(len: usize) -> String {
    random_bytes(len)
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ttl_to_millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis().max(1)).unwrap_or(u64::MAX)
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time must be after unix epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
