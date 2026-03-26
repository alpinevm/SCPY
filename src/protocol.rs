use scpy_crypto::{CipherEnvelope, RoomMeta};
use serde::{Deserialize, Serialize};

use crate::auth::OpaqueRoomRegistration;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRoomRequest {
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
    pub auth: OpaqueRoomRegistration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRoomResponse {
    pub room_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetRoomResponse {
    pub room_id: String,
    pub meta: RoomMeta,
    pub envelope: CipherEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClipboardRequest {
    pub envelope: CipherEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateClipboardResponse {
    pub room_id: String,
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClipboardEvent {
    pub room_id: String,
    pub envelope: CipherEnvelope,
}
