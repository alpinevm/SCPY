#![cfg(feature = "ssr")]

mod support;

use std::time::Duration;

use scpy_crypto::{create_room, decrypt_clipboard, encrypt_clipboard, unlock_room_key, KdfParams};
use secopy::api::{
    api_router, AppState, ClipboardEvent, GetRoomResponse, UpdateClipboardRequest,
    UpdateClipboardResponse,
};
use support::{authenticate_clipboard, cookie_client, create_clipboard, SseStream};

#[tokio::test]
async fn encrypted_room_flow_roundtrips_between_two_users_over_sse() {
    let state = AppState::memory(Duration::from_secs(60));
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

    let user_one_client = cookie_client();
    let user_two_client = cookie_client();
    let password = "shared test password";

    let user_one = create_room(password, "alpha clipboard", KdfParams::testing())
        .expect("user one should encrypt the initial room");
    let room_id = create_clipboard(&user_one_client, &base_url, password, &user_one).await;

    authenticate_clipboard(&user_two_client, &base_url, &room_id, password).await;
    let room_snapshot = user_two_client
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

    authenticate_clipboard(&user_one_client, &base_url, &room_id, password).await;
    let events_response = user_one_client
        .get(format!("{base_url}/api/rooms/{room_id}/events"))
        .send()
        .await
        .expect("sse subscription must connect");
    assert_eq!(events_response.status(), reqwest::StatusCode::OK);
    let mut sse = SseStream::new(events_response);

    let next_version = envelope.version + 1;
    let updated_envelope = encrypt_clipboard(&user_two_room_key, "beta clipboard", next_version)
        .expect("user two should re-encrypt the clipboard");
    let update_response = user_two_client
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
