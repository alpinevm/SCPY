use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, Script};
use scpy_crypto::{CipherEnvelope, RoomMeta};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};

use crate::allocator::{decode_room_id, encode_local_id, TieredAllocator};

const STORE_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredRoom {
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredRoomRecord {
    pub schema_version: u8,
    pub room_id: String,
    pub code_len: u8,
    pub local_id: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub expires_at_ms: u64,
    pub content_version: u64,
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
}

impl StoredRoomRecord {
    fn new(room_id: String, code_len: u8, local_id: u64, room: StoredRoom, ttl: Duration) -> Self {
        let now_ms = now_unix_ms();
        let expires_at_ms = now_ms.saturating_add(ttl_to_millis(ttl));
        let content_version = room.envelope.version;

        Self {
            schema_version: STORE_SCHEMA_VERSION,
            room_id,
            code_len,
            local_id,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            expires_at_ms,
            content_version,
            meta: room.meta,
            envelope: room.envelope,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeRoomResult {
    Freed,
    AlreadyFree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimResult {
    pub reclaimed: u64,
    pub cleaned: u64,
    pub scanned: u64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("allocator is exhausted")]
    AllocatorExhausted,
    #[error("room id is invalid")]
    InvalidRoomId,
    #[error("version conflict: current={current}, attempted={attempted}")]
    VersionConflict { current: u64, attempted: u64 },
    #[error("script protocol error: {0}")]
    ScriptProtocol(&'static str),
}

#[async_trait]
pub trait RoomStore: Send + Sync {
    async fn create(&self, room: StoredRoom, ttl: Duration)
        -> Result<StoredRoomRecord, StoreError>;
    async fn get(&self, room_id: &str) -> Result<Option<StoredRoomRecord>, StoreError>;
    async fn update(
        &self,
        room_id: &str,
        envelope: CipherEnvelope,
        ttl: Duration,
    ) -> Result<Option<StoredRoomRecord>, StoreError>;
}

#[derive(Clone, Default)]
pub struct MemoryRoomStore {
    rooms: Arc<RwLock<HashMap<String, ExpiringRoom>>>,
    allocator: Arc<Mutex<TieredAllocator>>,
}

#[derive(Clone)]
pub struct RedisRoomStore {
    connection: MultiplexedConnection,
    key_prefix: String,
    use_expiry_index: bool,
}

#[derive(Clone, Debug)]
struct ExpiringRoom {
    record: StoredRoomRecord,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct InitScriptResponse {
    status: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct CreateScriptResponse {
    status: String,
    error: Option<String>,
    code_len: Option<u8>,
    local_id: Option<u64>,
    expires_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WriteScriptResponse {
    status: String,
    error: Option<String>,
    room_id: Option<String>,
    content_version: Option<u64>,
    expires_at_ms: Option<u64>,
    current_content_version: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct FreeScriptResponse {
    status: String,
    result: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReclaimScriptResponse {
    status: String,
    reclaimed: Option<u64>,
    cleaned: Option<u64>,
    scanned: Option<u64>,
}

#[derive(Serialize)]
struct CreateScriptPayload<'a> {
    schema_version: u8,
    meta: &'a RoomMeta,
    envelope: &'a CipherEnvelope,
}

impl MemoryRoomStore {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(RwLock::new(HashMap::new())),
            allocator: Arc::new(Mutex::new(TieredAllocator::new())),
        }
    }

    async fn remove_if_expired(&self, room_id: &str, now: Instant) -> Option<StoredRoomRecord> {
        let mut rooms = self.rooms.write().await;
        let expired = rooms
            .get(room_id)
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.record.clone())?;
        rooms.remove(room_id);
        drop(rooms);

        let mut allocator = self.allocator.lock().await;
        let _ = allocator.free(expired.code_len, expired.local_id);
        Some(expired)
    }
}

impl RedisRoomStore {
    pub async fn connect(redis_url: &str) -> Result<Self, StoreError> {
        Self::connect_with_options(redis_url, false).await
    }

    pub async fn connect_with_options(
        redis_url: &str,
        use_expiry_index: bool,
    ) -> Result<Self, StoreError> {
        let client = redis::Client::open(redis_url)?;
        let mut connection = client.get_multiplexed_async_connection().await?;
        let store = Self {
            connection: connection.clone(),
            key_prefix: "scpy".to_string(),
            use_expiry_index,
        };

        let response: InitScriptResponse = serde_json::from_str(
            &Script::new(include_str!("../redis/alloc_init.lua"))
                .arg(&store.key_prefix)
                .invoke_async::<String>(&mut connection)
                .await?,
        )?;
        if response.status != "ok" {
            return Err(StoreError::ScriptProtocol(
                "alloc_init returned non-ok status",
            ));
        }
        if response.state != "initialized" && response.state != "already_initialized" {
            return Err(StoreError::ScriptProtocol(
                "alloc_init returned unknown state",
            ));
        }

        Ok(store)
    }

    pub async fn free(&self, room_id: &str) -> Result<FreeRoomResult, StoreError> {
        let allocation = decode_room_id(room_id).ok_or(StoreError::InvalidRoomId)?;
        let mut connection = self.connection.clone();
        let response: FreeScriptResponse = serde_json::from_str(
            &Script::new(include_str!("../redis/clip_free.lua"))
                .arg(&self.key_prefix)
                .arg(room_id)
                .arg(allocation.code_len)
                .arg(allocation.local_id)
                .arg(u8::from(self.use_expiry_index))
                .invoke_async::<String>(&mut connection)
                .await?,
        )?;

        if response.status != "ok" {
            return Err(StoreError::ScriptProtocol(
                "clip_free returned non-ok status",
            ));
        }

        match response.result.as_deref() {
            Some("freed") => Ok(FreeRoomResult::Freed),
            Some("already_free") => Ok(FreeRoomResult::AlreadyFree),
            _ => Err(StoreError::ScriptProtocol(
                "clip_free returned unknown result",
            )),
        }
    }

    pub async fn reclaim_expired(&self, limit: usize) -> Result<ReclaimResult, StoreError> {
        let mut connection = self.connection.clone();
        let response: ReclaimScriptResponse = serde_json::from_str(
            &Script::new(include_str!("../redis/clip_reclaim_expired.lua"))
                .arg(&self.key_prefix)
                .arg(now_unix_ms())
                .arg(limit.max(1))
                .invoke_async::<String>(&mut connection)
                .await?,
        )?;

        if response.status != "ok" {
            return Err(StoreError::ScriptProtocol(
                "clip_reclaim_expired returned non-ok status",
            ));
        }

        Ok(ReclaimResult {
            reclaimed: response.reclaimed.unwrap_or_default(),
            cleaned: response.cleaned.unwrap_or_default(),
            scanned: response.scanned.unwrap_or_default(),
        })
    }

    pub async fn free_intervals(&self, code_len: u8) -> Result<Vec<(u64, u64)>, StoreError> {
        let mut connection = self.connection.clone();
        let starts_key = format!("{}:alloc:{}:starts", self.key_prefix, code_len);
        let ends_key = format!("{}:alloc:{}:ends", self.key_prefix, code_len);
        let starts = redis::cmd("ZRANGE")
            .arg(&starts_key)
            .arg(0)
            .arg(-1)
            .query_async::<Vec<String>>(&mut connection)
            .await?;

        let mut intervals = Vec::with_capacity(starts.len());
        for start in starts {
            let end = redis::cmd("HGET")
                .arg(&ends_key)
                .arg(&start)
                .query_async::<Option<String>>(&mut connection)
                .await?
                .ok_or(StoreError::ScriptProtocol("missing interval end"))?;
            intervals.push((
                start
                    .parse::<u64>()
                    .map_err(|_| StoreError::ScriptProtocol("invalid interval start"))?,
                end.parse::<u64>()
                    .map_err(|_| StoreError::ScriptProtocol("invalid interval end"))?,
            ));
        }

        Ok(intervals)
    }

    fn clip_key_for_allocation(&self, code_len: u8, local_id: u64) -> String {
        format!("{}:clip:{code_len}:{local_id}", self.key_prefix)
    }

    fn clip_key(&self, room_id: &str) -> Result<String, StoreError> {
        let allocation = decode_room_id(room_id).ok_or(StoreError::InvalidRoomId)?;
        Ok(self.clip_key_for_allocation(allocation.code_len, allocation.local_id))
    }

    fn normalize_record(
        &self,
        mut record: StoredRoomRecord,
    ) -> Result<StoredRoomRecord, StoreError> {
        record.room_id = encode_local_id(record.code_len, record.local_id).ok_or(
            StoreError::ScriptProtocol("stored record had invalid allocation"),
        )?;
        Ok(record)
    }
}

#[async_trait]
impl RoomStore for MemoryRoomStore {
    async fn create(
        &self,
        room: StoredRoom,
        ttl: Duration,
    ) -> Result<StoredRoomRecord, StoreError> {
        let allocation = self
            .allocator
            .lock()
            .await
            .allocate()
            .ok_or(StoreError::AllocatorExhausted)?;
        let record = StoredRoomRecord::new(
            allocation.room_id.clone(),
            allocation.code_len,
            allocation.local_id,
            room,
            ttl,
        );
        let expires_at = Instant::now().checked_add(ttl).unwrap_or_else(Instant::now);

        self.rooms.write().await.insert(
            allocation.room_id,
            ExpiringRoom {
                record: record.clone(),
                expires_at,
            },
        );

        Ok(record)
    }

    async fn get(&self, room_id: &str) -> Result<Option<StoredRoomRecord>, StoreError> {
        let now = Instant::now();

        {
            let rooms = self.rooms.read().await;
            match rooms.get(room_id) {
                Some(entry) if entry.expires_at > now => return Ok(Some(entry.record.clone())),
                Some(_) => {}
                None => return Ok(None),
            }
        }

        let _ = self.remove_if_expired(room_id, now).await;
        Ok(None)
    }

    async fn update(
        &self,
        room_id: &str,
        envelope: CipherEnvelope,
        ttl: Duration,
    ) -> Result<Option<StoredRoomRecord>, StoreError> {
        let now = Instant::now();
        {
            let rooms = self.rooms.read().await;
            if let Some(entry) = rooms.get(room_id) {
                if entry.expires_at <= now {
                    drop(rooms);
                    let _ = self.remove_if_expired(room_id, now).await;
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

        let mut rooms = self.rooms.write().await;
        let entry = match rooms.get_mut(room_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        if envelope.version != entry.record.content_version + 1 {
            return Err(StoreError::VersionConflict {
                current: entry.record.content_version,
                attempted: envelope.version,
            });
        }

        let updated_at_ms = now_unix_ms();
        entry.record.envelope = envelope.clone();
        entry.record.content_version = envelope.version;
        entry.record.updated_at_ms = updated_at_ms;
        entry.record.expires_at_ms = updated_at_ms.saturating_add(ttl_to_millis(ttl));
        entry.expires_at = now.checked_add(ttl).unwrap_or_else(Instant::now);

        Ok(Some(entry.record.clone()))
    }
}

#[async_trait]
impl RoomStore for RedisRoomStore {
    async fn create(
        &self,
        room: StoredRoom,
        ttl: Duration,
    ) -> Result<StoredRoomRecord, StoreError> {
        let mut connection = self.connection.clone();
        let now_ms = now_unix_ms();
        let payload = serde_json::to_string(&CreateScriptPayload {
            schema_version: STORE_SCHEMA_VERSION,
            meta: &room.meta,
            envelope: &room.envelope,
        })?;
        let response: CreateScriptResponse = serde_json::from_str(
            &Script::new(include_str!("../redis/clip_create.lua"))
                .arg(&self.key_prefix)
                .arg(now_ms)
                .arg(ttl_to_millis(ttl))
                .arg(payload)
                .arg(u8::from(self.use_expiry_index))
                .invoke_async::<String>(&mut connection)
                .await?,
        )?;

        match response.status.as_str() {
            "ok" => {
                let code_len = response
                    .code_len
                    .ok_or(StoreError::ScriptProtocol("missing created code_len"))?;
                let local_id = response
                    .local_id
                    .ok_or(StoreError::ScriptProtocol("missing created local_id"))?;
                Ok(StoredRoomRecord {
                    schema_version: STORE_SCHEMA_VERSION,
                    room_id: encode_local_id(code_len, local_id)
                        .ok_or(StoreError::ScriptProtocol("created allocation was invalid"))?,
                    code_len,
                    local_id,
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    expires_at_ms: response
                        .expires_at_ms
                        .ok_or(StoreError::ScriptProtocol("missing created expires_at_ms"))?,
                    content_version: room.envelope.version,
                    meta: room.meta,
                    envelope: room.envelope,
                })
            }
            "err" if response.error.as_deref() == Some("allocator_exhausted") => {
                Err(StoreError::AllocatorExhausted)
            }
            _ => Err(StoreError::ScriptProtocol(
                "clip_create returned unknown response",
            )),
        }
    }

    async fn get(&self, room_id: &str) -> Result<Option<StoredRoomRecord>, StoreError> {
        let mut connection = self.connection.clone();
        let clip_key = match self.clip_key(room_id) {
            Ok(key) => key,
            Err(StoreError::InvalidRoomId) => return Ok(None),
            Err(other) => return Err(other),
        };
        let payload = redis::cmd("GET")
            .arg(clip_key)
            .query_async::<Option<String>>(&mut connection)
            .await?;

        payload
            .map(|json| {
                serde_json::from_str::<StoredRoomRecord>(&json)
                    .map_err(StoreError::from)
                    .and_then(|record| self.normalize_record(record))
            })
            .transpose()
    }

    async fn update(
        &self,
        room_id: &str,
        envelope: CipherEnvelope,
        ttl: Duration,
    ) -> Result<Option<StoredRoomRecord>, StoreError> {
        let allocation = match decode_room_id(room_id) {
            Some(allocation) => allocation,
            None => return Ok(None),
        };
        let mut connection = self.connection.clone();
        let response: WriteScriptResponse = serde_json::from_str(
            &Script::new(include_str!("../redis/clip_write.lua"))
                .arg(&self.key_prefix)
                .arg(room_id)
                .arg(allocation.code_len)
                .arg(allocation.local_id)
                .arg(now_unix_ms())
                .arg(ttl_to_millis(ttl))
                .arg(serde_json::to_string(&envelope)?)
                .arg(u8::from(self.use_expiry_index))
                .invoke_async::<String>(&mut connection)
                .await?,
        )?;

        match response.status.as_str() {
            "ok" => {
                let record = self.get(room_id).await?.ok_or(StoreError::ScriptProtocol(
                    "updated record missing after write",
                ))?;
                if response.room_id.as_deref() != Some(room_id) {
                    return Err(StoreError::ScriptProtocol(
                        "clip_write returned mismatched room_id",
                    ));
                }
                if response.content_version != Some(record.content_version)
                    || response.expires_at_ms != Some(record.expires_at_ms)
                {
                    return Err(StoreError::ScriptProtocol(
                        "clip_write returned mismatched state",
                    ));
                }
                Ok(Some(record))
            }
            "err" if response.error.as_deref() == Some("not_found") => Ok(None),
            "err" if response.error.as_deref() == Some("version_conflict") => {
                Err(StoreError::VersionConflict {
                    current: response.current_content_version.unwrap_or_default(),
                    attempted: envelope.version,
                })
            }
            _ => Err(StoreError::ScriptProtocol(
                "clip_write returned unknown response",
            )),
        }
    }
}

fn ttl_to_millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis().max(1)).unwrap_or(u64::MAX)
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after unix epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use scpy_crypto::{create_room, KdfParams};

    use crate::allocator::encode_local_id;

    use super::{FreeRoomResult, MemoryRoomStore, RoomStore, StoreError, StoredRoom};

    #[tokio::test]
    async fn memory_store_evicts_expired_rooms_on_get_and_reuses_their_code() {
        let store = MemoryRoomStore::new();
        let created =
            create_room("password", "hello world", KdfParams::testing()).expect("room must build");

        let first = store
            .create(
                StoredRoom {
                    meta: created.meta.clone(),
                    envelope: created.envelope.clone(),
                },
                Duration::from_millis(25),
            )
            .await
            .expect("room must store");
        assert_eq!(
            first.room_id,
            encode_local_id(3, 0).expect("public id must encode")
        );

        tokio::time::sleep(Duration::from_millis(40)).await;

        assert!(
            store
                .get(&first.room_id)
                .await
                .expect("get must succeed")
                .is_none(),
            "expired room should be lazily evicted"
        );

        let second = store
            .create(
                StoredRoom {
                    meta: created.meta,
                    envelope: created.envelope,
                },
                Duration::from_secs(1),
            )
            .await
            .expect("room must store");
        assert_eq!(
            second.room_id,
            encode_local_id(3, 0).expect("public id must encode"),
            "freed code should be reused"
        );
    }

    #[tokio::test]
    async fn memory_store_rejects_non_sequential_versions() {
        let store = MemoryRoomStore::new();
        let created =
            create_room("password", "hello world", KdfParams::testing()).expect("room must build");
        let record = store
            .create(
                StoredRoom {
                    meta: created.meta,
                    envelope: created.envelope.clone(),
                },
                Duration::from_secs(1),
            )
            .await
            .expect("create must succeed");

        let error = store
            .update(
                &record.room_id,
                scpy_crypto::encrypt_clipboard(
                    &created.room_key,
                    "next",
                    created.envelope.version + 2,
                )
                .expect("envelope must build"),
                Duration::from_secs(1),
            )
            .await
            .expect_err("non-sequential version must fail");

        match error {
            StoreError::VersionConflict { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn free_room_result_values_are_stable() {
        assert_eq!(FreeRoomResult::Freed, FreeRoomResult::Freed);
        assert_eq!(FreeRoomResult::AlreadyFree, FreeRoomResult::AlreadyFree);
    }
}
