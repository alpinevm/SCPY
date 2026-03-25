use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    extract::{FromRef, Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use scpy_crypto::CipherEnvelope;
use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

pub use crate::protocol::{
    ClipboardEvent, CreateRoomRequest, CreateRoomResponse, GetRoomResponse, UpdateClipboardRequest,
    UpdateClipboardResponse,
};
use crate::store::{MemoryRoomStore, RedisRoomStore, RoomStore, StoreError, StoredRoom};

const DEFAULT_ROOM_TTL: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Clone)]
pub struct AppState {
    inner: Arc<InnerState>,
}

struct InnerState {
    store: Arc<dyn RoomStore>,
    channels: Mutex<HashMap<String, broadcast::Sender<ClipboardEvent>>>,
    room_ttl: Duration,
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
        .route("/api/rooms", post(create_room))
        .route("/api/rooms/{room_id}", get(get_room))
        .route("/api/rooms/{room_id}/clipboard", post(update_clipboard))
        .route("/api/rooms/{room_id}/events", get(room_events))
}

impl AppState {
    pub fn new(store: Arc<dyn RoomStore>, room_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(InnerState {
                store,
                channels: Mutex::new(HashMap::new()),
                room_ttl,
            }),
        }
    }

    pub fn memory(room_ttl: Duration) -> Self {
        Self::new(Arc::new(MemoryRoomStore::new()), room_ttl)
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
        let state = Self::new(Arc::new(store.clone()), room_ttl);
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
        let stored = self
            .inner
            .store
            .create(
                StoredRoom {
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
        security_model: "e2ee-zero-knowledge-v1",
        seo_mode: "public-ssr-private-noindex",
    })
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
    Path(room_id): Path<String>,
) -> Result<Json<GetRoomResponse>, StatusCode> {
    state
        .get_room(&room_id)
        .await
        .map_err(store_error_to_status)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_clipboard(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Json(request): Json<UpdateClipboardRequest>,
) -> Result<Json<UpdateClipboardResponse>, StatusCode> {
    if request.envelope.version == 0 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
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
    Path(room_id): Path<String>,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
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
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
