#![cfg(feature = "ssr")]

mod support;

use std::{sync::Arc, time::Duration};

use futures_util::future::join_all;
use opaque_ke::ClientLoginFinishParameters;
use rand::rngs::OsRng;
use reqwest::StatusCode;
use scpy_crypto::{create_room, encrypt_clipboard, KdfParams};
use secopy::{
    api::{AppState, UpdateClipboardRequest},
    auth::new_server_setup,
    store::MemoryRoomStore,
};
use support::{
    authenticate_clipboard, cookie_client, create_clipboard, finish_authenticate_clipboard,
    login_finish_request, spawn_api_test_server, spawn_api_test_server_at,
    start_authenticate_clipboard, RedisTestInstance,
};

#[tokio::test]
async fn unauthenticated_clients_cannot_fetch_update_or_subscribe() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let unauthenticated_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let get_response = unauthenticated_client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("get must succeed");
    assert_eq!(get_response.status(), StatusCode::UNAUTHORIZED);

    let update_response = unauthenticated_client
        .post(format!("{base_url}/api/rooms/{room_id}/clipboard"))
        .json(&UpdateClipboardRequest {
            envelope: encrypt_clipboard(&created.room_key, "beta", created.envelope.version + 1)
                .expect("next envelope must build"),
        })
        .send()
        .await
        .expect("update must succeed");
    assert_eq!(update_response.status(), StatusCode::UNAUTHORIZED);

    let events_response = unauthenticated_client
        .get(format!("{base_url}/api/rooms/{room_id}/events"))
        .send()
        .await
        .expect("events request must succeed");
    assert_eq!(events_response.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_login_fails_uniformly_for_wrong_password_and_missing_clipboard() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let wrong_password_client = cookie_client();
    let missing_room_client = cookie_client();

    let created = create_room("correct-password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "correct-password", &created).await;

    let (wrong_start, wrong_start_response) = start_authenticate_clipboard(
        &wrong_password_client,
        &base_url,
        &room_id,
        "wrong-password",
    )
    .await;
    let mut wrong_rng = OsRng;
    assert!(wrong_start
        .state
        .finish(
            &mut wrong_rng,
            b"wrong-password",
            wrong_start_response.message,
            ClientLoginFinishParameters::default(),
        )
        .is_err());
    let wrong_get = wrong_password_client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("wrong-password get must succeed");
    assert_eq!(wrong_get.status(), StatusCode::UNAUTHORIZED);

    let (missing_start, missing_start_response) =
        start_authenticate_clipboard(&missing_room_client, &base_url, "222", "wrong-password")
            .await;
    let mut missing_rng = OsRng;
    assert!(missing_start
        .state
        .finish(
            &mut missing_rng,
            b"wrong-password",
            missing_start_response.message,
            ClientLoginFinishParameters::default(),
        )
        .is_err());
    let missing_get = missing_room_client
        .get(format!("{base_url}/api/rooms/222"))
        .send()
        .await
        .expect("missing-room get must succeed");
    assert_eq!(missing_get.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_sessions_are_scoped_to_a_single_clipboard() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let first = create_room("password-a", "alpha", KdfParams::testing()).expect("first room");
    let second = create_room("password-b", "beta", KdfParams::testing()).expect("second room");
    let first_room_id = create_clipboard(&creator_client, &base_url, "password-a", &first).await;
    let second_room_id = create_clipboard(&creator_client, &base_url, "password-b", &second).await;

    authenticate_clipboard(&reader_client, &base_url, &first_room_id, "password-a").await;

    let first_get = reader_client
        .get(format!("{base_url}/api/rooms/{first_room_id}"))
        .send()
        .await
        .expect("first get must succeed");
    assert_eq!(first_get.status(), StatusCode::OK);

    let second_get = reader_client
        .get(format!("{base_url}/api/rooms/{second_room_id}"))
        .send()
        .await
        .expect("second get must succeed");
    assert_eq!(second_get.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_login_state_expires_before_finish() {
    let state = AppState::new(
        Arc::new(MemoryRoomStore::new()),
        new_server_setup(),
        Duration::from_secs(60),
        Duration::from_millis(20),
        Duration::from_secs(60),
    );
    let server = spawn_api_test_server(state).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let (login_start, login_start_response) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let login_finish = finish_authenticate_clipboard(
        &reader_client,
        &base_url,
        "password",
        login_start,
        login_start_response,
    )
    .await;
    assert_eq!(login_finish.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_same_cookie_jar_can_hold_sessions_for_multiple_clipboards() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let first = create_room("password-a", "alpha", KdfParams::testing()).expect("first room");
    let second = create_room("password-b", "beta", KdfParams::testing()).expect("second room");
    let first_room_id = create_clipboard(&creator_client, &base_url, "password-a", &first).await;
    let second_room_id = create_clipboard(&creator_client, &base_url, "password-b", &second).await;

    authenticate_clipboard(&reader_client, &base_url, &first_room_id, "password-a").await;
    authenticate_clipboard(&reader_client, &base_url, &second_room_id, "password-b").await;

    let first_get = reader_client
        .get(format!("{base_url}/api/rooms/{first_room_id}"))
        .send()
        .await
        .expect("first get must succeed");
    assert_eq!(first_get.status(), StatusCode::OK);

    let second_get = reader_client
        .get(format!("{base_url}/api/rooms/{second_room_id}"))
        .send()
        .await
        .expect("second get must succeed");
    assert_eq!(second_get.status(), StatusCode::OK);

    server.abort();
}

#[tokio::test]
async fn opaque_login_session_id_cannot_be_reused_after_successful_finish() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let (login_start, login_start_response) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;
    let finish_request = login_finish_request("password", login_start, login_start_response);

    let first_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request)
        .send()
        .await
        .expect("first finish must succeed");
    assert_eq!(first_finish.status(), StatusCode::OK);

    let replay_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request)
        .send()
        .await
        .expect("replayed finish must resolve");
    assert_eq!(replay_finish.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_malformed_login_start_payload_is_rejected() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let response = reader_client
        .post(format!("{base_url}/api/auth/login/start"))
        .json(&serde_json::json!({
            "room_id": room_id,
            "message": {}
        }))
        .send()
        .await
        .expect("malformed login start must resolve");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    server.abort();
}

#[tokio::test]
async fn opaque_malformed_login_finish_payload_is_rejected_without_consuming_the_login_state() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let (login_start, login_start_response) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;
    let finish_request =
        login_finish_request("password", login_start, login_start_response.clone());

    let malformed_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&serde_json::json!({
            "login_session_id": login_start_response.login_session_id,
            "message": {}
        }))
        .send()
        .await
        .expect("malformed finish must resolve");
    assert_eq!(malformed_finish.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let valid_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request)
        .send()
        .await
        .expect("valid finish must succeed");
    assert_eq!(valid_finish.status(), StatusCode::OK);

    server.abort();
}

#[tokio::test]
async fn opaque_mismatched_login_finalization_is_rejected_and_consumes_only_the_target_session() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;

    let (login_start_one, login_start_response_one) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;
    let (login_start_two, login_start_response_two) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;

    let finish_request_one = login_finish_request(
        "password",
        login_start_one,
        login_start_response_one.clone(),
    );
    let finish_request_two = login_finish_request(
        "password",
        login_start_two,
        login_start_response_two.clone(),
    );

    let mismatched_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&serde_json::json!({
            "login_session_id": login_start_response_two.login_session_id,
            "message": finish_request_one.message.clone()
        }))
        .send()
        .await
        .expect("mismatched finish must resolve");
    assert_eq!(mismatched_finish.status(), StatusCode::UNAUTHORIZED);

    let untouched_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request_one)
        .send()
        .await
        .expect("untouched finish must succeed");
    assert_eq!(untouched_finish.status(), StatusCode::OK);

    let consumed_finish = reader_client
        .post(format!("{base_url}/api/auth/login/finish"))
        .json(&finish_request_two)
        .send()
        .await
        .expect("consumed finish must resolve");
    assert_eq!(consumed_finish.status(), StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn opaque_parallel_logins_to_the_same_clipboard_all_succeed_and_authorize() {
    let server = spawn_api_test_server(AppState::memory(Duration::from_secs(60))).await;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let password = "parallel-password";

    let created = create_room(password, "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, password, &created).await;

    let results = join_all((0..8).map(|_| {
        let base_url = base_url.clone();
        let room_id = room_id.clone();
        async move {
            let client = cookie_client();
            authenticate_clipboard(&client, &base_url, &room_id, password).await;
            client
                .get(format!("{base_url}/api/rooms/{room_id}"))
                .send()
                .await
                .expect("parallel get must resolve")
                .status()
        }
    }))
    .await;

    assert!(results.into_iter().all(|status| status == StatusCode::OK));

    server.abort();
}

#[tokio::test]
async fn opaque_login_can_finish_after_server_and_redis_restart() {
    let redis = RedisTestInstance::start().await;
    let server = spawn_api_test_server(
        AppState::redis(&redis.redis_url(), Duration::from_secs(60))
            .await
            .expect("redis-backed app state must connect"),
    )
    .await;
    let addr = server.addr;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;
    let (login_start, login_start_response) =
        start_authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;

    server.abort();
    redis.restart().await;

    let restarted = spawn_api_test_server_at(
        addr,
        AppState::redis(&redis.redis_url(), Duration::from_secs(60))
            .await
            .expect("redis-backed app state must reconnect"),
    )
    .await;

    let login_finish = finish_authenticate_clipboard(
        &reader_client,
        &base_url,
        "password",
        login_start,
        login_start_response,
    )
    .await;
    assert_eq!(login_finish.status(), StatusCode::OK);

    let room_get = reader_client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("room get must resolve after restart");
    assert_eq!(room_get.status(), StatusCode::OK);

    restarted.abort();
}

#[tokio::test]
async fn opaque_session_survives_server_and_redis_restart() {
    let redis = RedisTestInstance::start().await;
    let server = spawn_api_test_server(
        AppState::redis(&redis.redis_url(), Duration::from_secs(60))
            .await
            .expect("redis-backed app state must connect"),
    )
    .await;
    let addr = server.addr;
    let base_url = server.base_url.clone();
    let creator_client = cookie_client();
    let reader_client = cookie_client();

    let created = create_room("password", "alpha", KdfParams::testing()).expect("room");
    let room_id = create_clipboard(&creator_client, &base_url, "password", &created).await;
    authenticate_clipboard(&reader_client, &base_url, &room_id, "password").await;

    let before_restart = reader_client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("room get before restart must resolve");
    assert_eq!(before_restart.status(), StatusCode::OK);

    server.abort();
    redis.restart().await;

    let restarted = spawn_api_test_server_at(
        addr,
        AppState::redis(&redis.redis_url(), Duration::from_secs(60))
            .await
            .expect("redis-backed app state must reconnect"),
    )
    .await;

    let after_restart = reader_client
        .get(format!("{base_url}/api/rooms/{room_id}"))
        .send()
        .await
        .expect("room get after restart must resolve");
    assert_eq!(after_restart.status(), StatusCode::OK);

    restarted.abort();
}
