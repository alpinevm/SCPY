#![cfg(feature = "ssr")]

mod support;

use std::time::Duration;

use scpy_crypto::{create_room, decrypt_clipboard, encrypt_clipboard, unlock_room_key, KdfParams};
use secopy::api::{
    api_router, AppState, ClipboardEvent, CreateRoomRequest, CreateRoomResponse, GetRoomResponse,
    UpdateClipboardRequest, UpdateClipboardResponse,
};
use support::{RedisTestInstance, SseStream};

#[tokio::test]
async fn encrypted_room_flow_roundtrips_over_redis_backed_store() {
    let redis = RedisTestInstance::start().await;
    let state = AppState::redis(&redis.redis_url(), Duration::from_secs(60))
        .await
        .expect("redis-backed app state must connect");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("address must resolve")
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, api_router::<AppState>().with_state(state))
            .await
            .expect("test server must run");
    });

    let client = reqwest::Client::new();
    let password = "shared redis test password";

    let user_one = create_room(password, "alpha clipboard", KdfParams::testing())
        .expect("user one should encrypt the initial room");
    let create_response = client
        .post(format!("{base_url}/api/rooms"))
        .json(&CreateRoomRequest {
            meta: user_one.meta.clone(),
            envelope: user_one.envelope.clone(),
        })
        .send()
        .await
        .expect("create room request must succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let CreateRoomResponse { room_id } = create_response
        .json()
        .await
        .expect("create room response must deserialize");

    let room_snapshot = client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("room fetch must succeed");
    assert_eq!(room_snapshot.status(), reqwest::StatusCode::OK);
    let GetRoomResponse {
        meta,
        envelope,
        room_id: fetched_room_id,
    } = room_snapshot
        .json()
        .await
        .expect("room snapshot must deserialize");
    assert_eq!(fetched_room_id, room_id);

    let user_two_room_key =
        unlock_room_key(password, &meta).expect("user two should unlock the room locally");
    let user_two_plaintext = decrypt_clipboard(&user_two_room_key, &envelope)
        .expect("user two should decrypt the initial ciphertext");
    assert_eq!(user_two_plaintext, "alpha clipboard");

    let events_response = client
        .get(format!("{base_url}/api/rooms/{room_id}/events"))
        .send()
        .await
        .expect("sse subscription must connect");
    assert_eq!(events_response.status(), reqwest::StatusCode::OK);
    let mut sse = SseStream::new(events_response);

    let next_version = envelope.version + 1;
    let updated_envelope = encrypt_clipboard(&user_two_room_key, "beta clipboard", next_version)
        .expect("user two should re-encrypt the clipboard");
    let update_response = client
        .post(format!("{base_url}/api/rooms/{room_id}/clipboard"))
        .json(&UpdateClipboardRequest {
            envelope: updated_envelope,
        })
        .send()
        .await
        .expect("clipboard update must succeed");
    assert_eq!(update_response.status(), reqwest::StatusCode::OK);
    let UpdateClipboardResponse { version, .. } = update_response
        .json()
        .await
        .expect("update response must deserialize");
    assert_eq!(version, next_version);

    let ClipboardEvent {
        room_id: event_room_id,
        envelope: event_envelope,
    } = tokio::time::timeout(Duration::from_secs(5), sse.next_event())
        .await
        .expect("sse event should arrive in time")
        .expect("sse event should parse");
    assert_eq!(event_room_id, room_id);

    let user_one_plaintext = decrypt_clipboard(&user_one.room_key, &event_envelope)
        .expect("user one should decrypt the SSE-delivered ciphertext");
    assert_eq!(user_one_plaintext, "beta clipboard");

    server.abort();
}

#[tokio::test]
async fn redis_background_reclaimer_returns_expired_codes_to_the_live_app() {
    let redis = RedisTestInstance::start().await;
    let state = AppState::redis_with_reclaimer(
        &redis.redis_url(),
        Duration::from_millis(30),
        Duration::from_millis(10),
        32,
    )
    .await
    .expect("redis-backed app state must connect");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("address must resolve")
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, api_router::<AppState>().with_state(state))
            .await
            .expect("test server must run");
    });

    let client = reqwest::Client::new();
    let first_room = create_room("password one", "alpha clipboard", KdfParams::testing())
        .expect("first room should encrypt");
    let first_response = client
        .post(format!("{base_url}/api/rooms"))
        .json(&CreateRoomRequest {
            meta: first_room.meta,
            envelope: first_room.envelope,
        })
        .send()
        .await
        .expect("create request must succeed");
    assert_eq!(first_response.status(), reqwest::StatusCode::CREATED);
    let CreateRoomResponse {
        room_id: first_room_id,
    } = first_response
        .json()
        .await
        .expect("create response must deserialize");

    tokio::time::sleep(Duration::from_millis(80)).await;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .get(format!("{base_url}/api/rooms/{first_room_id}"))
                .send()
                .await
                .expect("room fetch must succeed");
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("room should expire from the live app");

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if redis.expiring_members().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("background reclaimer should drain the expiry index");

    let second_room = create_room("password two", "beta clipboard", KdfParams::testing())
        .expect("second room should encrypt");
    let second_response = client
        .post(format!("{base_url}/api/rooms"))
        .json(&CreateRoomRequest {
            meta: second_room.meta,
            envelope: second_room.envelope,
        })
        .send()
        .await
        .expect("second create request must succeed");
    assert_eq!(second_response.status(), reqwest::StatusCode::CREATED);
    let CreateRoomResponse {
        room_id: second_room_id,
    } = second_response
        .json()
        .await
        .expect("second create response must deserialize");

    assert_eq!(second_room_id, first_room_id);

    server.abort();
}
