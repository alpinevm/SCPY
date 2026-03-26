#![cfg(feature = "ssr")]

mod support;

use std::{collections::BTreeSet, time::Duration};

use opaque_ke::{ClientRegistrationFinishParameters, ServerRegistration};
use rand::rngs::OsRng;
use scpy_crypto::{create_room, encrypt_clipboard, KdfParams};
use secopy::{
    allocator::{decode_room_id, encode_local_id, tier_capacity, FreeOutcome, TieredAllocator},
    auth::{new_server_setup, OpaqueClientRegistration, StoredOpaqueRegistration},
    store::{FreeRoomResult, RedisRoomStore, RoomStore, StoreError, StoredRoom},
};
use support::RedisTestInstance;

fn test_registration(password: &str) -> StoredOpaqueRegistration {
    let credential_id = b"redis-integration-auth".to_vec();
    let server_setup = new_server_setup();
    let mut rng = OsRng;
    let registration_start =
        OpaqueClientRegistration::start(&mut rng, password.as_bytes()).expect("must start");
    let registration_response =
        ServerRegistration::start(&server_setup, registration_start.message, &credential_id)
            .expect("must build response");
    let registration_finish = registration_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            registration_response.message,
            ClientRegistrationFinishParameters::default(),
        )
        .expect("must finish registration");

    StoredOpaqueRegistration {
        credential_id,
        password_file: ServerRegistration::finish(registration_finish.message),
    }
}

fn encrypted_room(plaintext: &str) -> (StoredRoom, scpy_crypto::CreatedRoom) {
    let created =
        create_room("redis allocator password", plaintext, KdfParams::testing()).expect("room");
    (
        StoredRoom {
            auth: test_registration("redis allocator password"),
            meta: created.meta.clone(),
            envelope: created.envelope.clone(),
        },
        created,
    )
}

fn build_reference_allocator(tiers: &[(u8, Vec<(u64, u64)>)]) -> TieredAllocator {
    let mut allocator = TieredAllocator::empty();
    for code_len in [3_u8, 4, 5, 6] {
        let intervals = tiers
            .iter()
            .find(|(tier, _)| *tier == code_len)
            .map(|(_, intervals)| intervals.clone())
            .unwrap_or_default();
        allocator
            .seed_tier(code_len, &intervals)
            .expect("tier intervals must seed");
    }
    allocator
}

async fn connected_store() -> (RedisTestInstance, RedisRoomStore) {
    let redis = RedisTestInstance::start().await;
    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must connect");
    (redis, store)
}

async fn connected_store_with_expiry_index() -> (RedisTestInstance, RedisRoomStore) {
    let redis = RedisTestInstance::start().await;
    let store = RedisRoomStore::connect_with_options(&redis.redis_url(), true)
        .await
        .expect("redis store with expiry index must connect");
    (redis, store)
}

fn public_id(code_len: u8, local_id: u64) -> String {
    encode_local_id(code_len, local_id).expect("public id must encode")
}

fn internal_member(code_len: u8, local_id: u64) -> String {
    format!("{code_len}:{local_id}")
}

macro_rules! first_code_tier_test {
    ($name:ident, $code_len:expr) => {
        #[tokio::test]
        async fn $name() {
            let (redis, store) = connected_store().await;
            redis.seed_allocator(&[($code_len, vec![(0, 0)])]).await;

            let (room, _) = encrypted_room("first code");
            let record = store
                .create(room, Duration::from_secs(60))
                .await
                .expect("room must create");

            assert_eq!(record.room_id, public_id($code_len, 0));
        }
    };
}

macro_rules! last_code_tier_test {
    ($name:ident, $code_len:expr) => {
        #[tokio::test]
        async fn $name() {
            let (redis, store) = connected_store().await;
            let last = tier_capacity($code_len).expect("tier") - 1;
            redis
                .seed_allocator(&[($code_len, vec![(last, last)])])
                .await;

            let (room, _) = encrypted_room("last code");
            let record = store
                .create(room, Duration::from_secs(60))
                .await
                .expect("room must create");

            assert_eq!(record.room_id, public_id($code_len, last));
        }
    };
}

first_code_tier_test!(redis_store_allocates_first_code_in_3_char_tier, 3);
first_code_tier_test!(redis_store_allocates_first_code_in_4_char_tier, 4);
first_code_tier_test!(redis_store_allocates_first_code_in_5_char_tier, 5);
first_code_tier_test!(redis_store_allocates_first_code_in_6_char_tier, 6);

last_code_tier_test!(redis_store_allocates_last_code_in_3_char_tier, 3);
last_code_tier_test!(redis_store_allocates_last_code_in_4_char_tier, 4);
last_code_tier_test!(redis_store_allocates_last_code_in_5_char_tier, 5);
last_code_tier_test!(redis_store_allocates_last_code_in_6_char_tier, 6);

#[tokio::test]
async fn redis_store_allocates_the_first_three_character_codes_first() {
    let (_redis, store) = connected_store().await;

    let (room_one, _) = encrypted_room("alpha");
    let (room_two, _) = encrypted_room("beta");
    let (room_three, _) = encrypted_room("gamma");

    let first = store
        .create(room_one, Duration::from_secs(60))
        .await
        .expect("first room must create");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("second room must create");
    let third = store
        .create(room_three, Duration::from_secs(60))
        .await
        .expect("third room must create");

    assert_eq!(first.room_id, public_id(3, 0));
    assert_eq!(second.room_id, public_id(3, 1));
    assert_eq!(third.room_id, public_id(3, 2));
}

#[tokio::test]
async fn redis_store_rolls_to_the_next_tier_after_seeded_exhaustion() {
    let (redis, store) = connected_store().await;
    redis
        .seed_allocator(&[(3, vec![(0, 1)]), (4, vec![(0, 1)])])
        .await;

    let (room_one, _) = encrypted_room("alpha");
    let (room_two, _) = encrypted_room("beta");
    let (room_three, _) = encrypted_room("gamma");

    let first = store
        .create(room_one, Duration::from_secs(60))
        .await
        .expect("first room must create");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("second room must create");
    let third = store
        .create(room_three, Duration::from_secs(60))
        .await
        .expect("third room must create");

    assert_eq!(first.room_id, public_id(3, 0));
    assert_eq!(second.room_id, public_id(3, 1));
    assert_eq!(third.room_id, public_id(4, 0));
}

#[tokio::test]
async fn redis_store_returns_allocator_exhausted_when_all_tiers_are_empty() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[]).await;

    let (room, _) = encrypted_room("alpha");
    let error = store
        .create(room, Duration::from_secs(60))
        .await
        .expect_err("empty allocator must fail");
    assert!(matches!(error, StoreError::AllocatorExhausted));
}

#[tokio::test]
async fn redis_store_rejects_invalid_room_ids_on_free() {
    let (_redis, store) = connected_store().await;

    let error = store
        .free("OOO")
        .await
        .expect_err("invalid room id must fail");
    assert!(matches!(error, StoreError::InvalidRoomId));
}

#[tokio::test]
async fn redis_store_get_treats_invalid_public_ids_as_missing() {
    let (_redis, store) = connected_store().await;
    assert!(store.get("OOO").await.expect("get must succeed").is_none());
}

#[tokio::test]
async fn redis_store_update_treats_invalid_public_ids_as_missing() {
    let (_redis, store) = connected_store().await;
    let (room, created) = encrypted_room("alpha");
    let next_envelope = encrypt_clipboard(&created.room_key, "beta", room.envelope.version + 1)
        .expect("next envelope must encrypt");
    assert!(store
        .update("OOO", next_envelope, Duration::from_secs(60))
        .await
        .expect("update must succeed")
        .is_none());
}

#[tokio::test]
async fn redis_store_free_merges_both_sides_and_is_idempotent() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(0, 0), (2, 2)])]).await;

    let first_free = store
        .free(&public_id(3, 1))
        .await
        .expect("free must succeed");
    assert_eq!(first_free, FreeRoomResult::Freed);
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(0, 2)]
    );

    let second_free = store
        .free(&public_id(3, 1))
        .await
        .expect("repeat free must succeed");
    assert_eq!(second_free, FreeRoomResult::AlreadyFree);
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(0, 2)]
    );
}

#[tokio::test]
async fn redis_store_free_handles_left_only_and_right_only_merges() {
    let (redis, store) = connected_store().await;

    redis.seed_allocator(&[(3, vec![(0, 0)])]).await;
    assert_eq!(
        store
            .free(&public_id(3, 1))
            .await
            .expect("left merge free must succeed"),
        FreeRoomResult::Freed
    );
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(0, 1)]
    );

    redis.seed_allocator(&[(3, vec![(2, 2)])]).await;
    assert_eq!(
        store
            .free(&public_id(3, 1))
            .await
            .expect("right merge free must succeed"),
        FreeRoomResult::Freed
    );
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(1, 2)]
    );
}

#[tokio::test]
async fn redis_store_free_handles_max_boundary_merge() {
    let (redis, store) = connected_store().await;
    let last = tier_capacity(3).expect("tier") - 1;
    redis
        .seed_allocator(&[(3, vec![(last - 1, last - 1)])])
        .await;

    let last_code = encode_local_id(3, last).expect("last code must encode");
    assert_eq!(
        store
            .free(&last_code)
            .await
            .expect("boundary free must succeed"),
        FreeRoomResult::Freed
    );
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(last - 1, last)]
    );
}

#[tokio::test]
async fn redis_store_update_refreshes_ttl_and_enforces_sequential_versions() {
    let (_redis, store) = connected_store().await;
    let (room, created) = encrypted_room("alpha");

    let record = store
        .create(room, Duration::from_millis(60))
        .await
        .expect("room must create");

    tokio::time::sleep(Duration::from_millis(20)).await;

    let next_envelope = encrypt_clipboard(&created.room_key, "beta", record.content_version + 1)
        .expect("next envelope must encrypt");
    let updated = store
        .update(&record.room_id, next_envelope, Duration::from_millis(200))
        .await
        .expect("update must succeed")
        .expect("updated room must exist");
    assert_eq!(updated.room_id, record.room_id);
    assert_eq!(updated.content_version, record.content_version + 1);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        store
            .get(&record.room_id)
            .await
            .expect("get must succeed")
            .is_some(),
        "ttl should have been refreshed by the update"
    );

    let skipped_envelope =
        encrypt_clipboard(&created.room_key, "gamma", updated.content_version + 2)
            .expect("skipped envelope must encrypt");
    let error = store
        .update(&record.room_id, skipped_envelope, Duration::from_secs(1))
        .await
        .expect_err("non-sequential version must fail");
    match error {
        StoreError::VersionConflict { current, attempted } => {
            assert_eq!(current, updated.content_version);
            assert_eq!(attempted, updated.content_version + 2);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn redis_store_can_reuse_an_expired_code_after_explicit_free() {
    let (_redis, store) = connected_store().await;
    let (room_one, _) = encrypted_room("alpha");

    let first = store
        .create(room_one, Duration::from_millis(30))
        .await
        .expect("room must create");
    assert_eq!(first.room_id, public_id(3, 0));

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        store
            .get(&first.room_id)
            .await
            .expect("get must succeed")
            .is_none(),
        "room should have expired from redis"
    );

    assert_eq!(
        store.free(&first.room_id).await.expect("free must succeed"),
        FreeRoomResult::Freed
    );

    let (room_two, _) = encrypted_room("beta");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("room must create");
    assert_eq!(
        second.room_id,
        public_id(3, 0),
        "freed code should be reused first"
    );
}

#[tokio::test]
async fn redis_store_persists_public_ids_but_keys_by_internal_allocator_coordinates() {
    let (redis, store) = connected_store().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("room must create");

    let decoded = decode_room_id(&record.room_id).expect("public id must decode");
    assert_eq!(decoded.code_len, record.code_len);
    assert_eq!(decoded.local_id, record.local_id);

    let mut connection = redis.connection().await;
    let payload = redis::cmd("GET")
        .arg(format!("scpy:clip:{}:{}", record.code_len, record.local_id))
        .query_async::<Option<String>>(&mut connection)
        .await
        .expect("internal key must be readable")
        .expect("record must exist");
    let persisted: secopy::store::StoredRoomRecord =
        serde_json::from_str(&payload).expect("stored record must deserialize");
    assert_eq!(persisted.code_len, record.code_len);
    assert_eq!(persisted.local_id, record.local_id);
    assert_ne!(persisted.room_id, record.room_id);
}

#[tokio::test]
async fn redis_store_free_of_a_non_adjacent_code_creates_a_singleton_gap() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(0, 0), (3, 3)])]).await;

    assert_eq!(
        store
            .free(&public_id(3, 2))
            .await
            .expect("free must succeed"),
        FreeRoomResult::Freed
    );
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(0, 0), (2, 3)]
    );
}

#[tokio::test]
async fn redis_store_reuses_the_lowest_available_gap_before_higher_ids() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(5, 5), (8, 8)])]).await;

    let (room_one, _) = encrypted_room("alpha");
    let (room_two, _) = encrypted_room("beta");
    let first = store
        .create(room_one, Duration::from_secs(60))
        .await
        .expect("room must create");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("room must create");

    assert_eq!(first.room_id, public_id(3, 5));
    assert_eq!(second.room_id, public_id(3, 8));
}

#[tokio::test]
async fn redis_store_create_with_expiry_index_tracks_the_internal_member() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("room must create");

    assert_eq!(
        redis.expiring_members().await,
        vec![internal_member(record.code_len, record.local_id)]
    );
    assert!(redis
        .expiring_score(&internal_member(record.code_len, record.local_id))
        .await
        .is_some());
}

#[tokio::test]
async fn redis_store_update_with_expiry_index_refreshes_the_internal_member_score() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, created) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_millis(60))
        .await
        .expect("room must create");
    let member = internal_member(record.code_len, record.local_id);
    let first_score = redis
        .expiring_score(&member)
        .await
        .expect("member must exist");

    tokio::time::sleep(Duration::from_millis(20)).await;
    let next_envelope = encrypt_clipboard(&created.room_key, "beta", record.content_version + 1)
        .expect("next envelope must encrypt");
    let updated = store
        .update(&record.room_id, next_envelope, Duration::from_secs(1))
        .await
        .expect("update must succeed")
        .expect("record must exist");
    let refreshed_score = redis
        .expiring_score(&member)
        .await
        .expect("member must still exist");

    assert_eq!(updated.room_id, record.room_id);
    assert!(refreshed_score > first_score);
}

#[tokio::test]
async fn redis_store_free_with_expiry_index_removes_the_internal_member() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("room must create");
    let member = internal_member(record.code_len, record.local_id);

    assert_eq!(
        store
            .free(&record.room_id)
            .await
            .expect("free must succeed"),
        FreeRoomResult::Freed
    );
    assert!(redis.expiring_members().await.is_empty());
    assert!(redis.expiring_score(&member).await.is_none());
}

#[tokio::test]
async fn redis_store_expiry_index_survives_restart() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("room must create");
    let member = internal_member(record.code_len, record.local_id);
    let first_score = redis
        .expiring_score(&member)
        .await
        .expect("member must exist");

    tokio::time::sleep(Duration::from_millis(1200)).await;
    redis.restart().await;

    let reopened = RedisRoomStore::connect_with_options(&redis.redis_url(), true)
        .await
        .expect("redis store must reconnect");
    let persisted = reopened
        .get(&record.room_id)
        .await
        .expect("get must succeed")
        .expect("record must exist");
    assert_eq!(persisted.room_id, record.room_id);
    assert_eq!(
        redis
            .expiring_score(&member)
            .await
            .expect("member must survive restart"),
        first_score
    );
}

#[tokio::test]
async fn redis_store_reclaim_expired_is_a_noop_before_any_entry_is_due() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(5))
        .await
        .expect("room must create");

    let result = store
        .reclaim_expired(10)
        .await
        .expect("reclaim must succeed");
    assert_eq!(result.reclaimed, 0);
    assert_eq!(result.cleaned, 0);
    assert_eq!(result.scanned, 0);
    assert_eq!(
        redis.expiring_members().await,
        vec![internal_member(record.code_len, record.local_id)]
    );
}

#[tokio::test]
async fn redis_store_reclaim_expired_reinserts_the_expired_code_into_the_allocator() {
    let (_redis, store) = connected_store_with_expiry_index().await;
    let (room_one, _) = encrypted_room("alpha");
    let first = store
        .create(room_one, Duration::from_millis(30))
        .await
        .expect("room must create");

    tokio::time::sleep(Duration::from_millis(60)).await;

    let result = store
        .reclaim_expired(10)
        .await
        .expect("reclaim must succeed");
    assert_eq!(result.reclaimed, 1);
    assert_eq!(result.cleaned, 0);
    assert_eq!(result.scanned, 1);

    let (room_two, _) = encrypted_room("beta");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("room must create");
    assert_eq!(second.room_id, first.room_id);
}

#[tokio::test]
async fn redis_store_reclaim_expired_respects_the_batch_limit() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let mut allocated = Vec::new();
    for plaintext in ["alpha", "beta", "gamma"] {
        let (room, _) = encrypted_room(plaintext);
        allocated.push(
            store
                .create(room, Duration::from_millis(30))
                .await
                .expect("room must create"),
        );
    }

    tokio::time::sleep(Duration::from_millis(60)).await;

    let first_pass = store
        .reclaim_expired(2)
        .await
        .expect("reclaim must succeed");
    assert_eq!(first_pass.reclaimed, 2);
    assert_eq!(first_pass.cleaned, 0);
    assert_eq!(first_pass.scanned, 2);
    assert_eq!(redis.expiring_members().await.len(), 1);

    let second_pass = store
        .reclaim_expired(2)
        .await
        .expect("reclaim must succeed");
    assert_eq!(second_pass.reclaimed, 1);
    assert_eq!(second_pass.cleaned, 0);
    assert_eq!(second_pass.scanned, 1);
    assert!(redis.expiring_members().await.is_empty());

    let mut reused = Vec::new();
    for plaintext in ["delta", "epsilon", "zeta"] {
        let (room, _) = encrypted_room(plaintext);
        reused.push(
            store
                .create(room, Duration::from_secs(60))
                .await
                .expect("room must create")
                .room_id,
        );
    }
    assert_eq!(
        reused,
        allocated
            .into_iter()
            .map(|record| record.room_id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn redis_store_reclaim_expired_cleans_stale_index_entries_for_already_free_codes() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let mut connection = redis.connection().await;
    redis::cmd("ZADD")
        .arg("scpy:clip:expiring")
        .arg(0)
        .arg("3:7")
        .query_async::<()>(&mut connection)
        .await
        .expect("stale expiring member must seed");

    let result = store
        .reclaim_expired(10)
        .await
        .expect("reclaim must succeed");
    assert_eq!(result.reclaimed, 0);
    assert_eq!(result.cleaned, 1);
    assert_eq!(result.scanned, 1);
    assert!(redis.expiring_members().await.is_empty());
}

#[tokio::test]
async fn redis_store_reclaim_expired_survives_restart_and_recovers_the_code() {
    let (redis, store) = connected_store_with_expiry_index().await;
    let (room, _) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_millis(30))
        .await
        .expect("room must create");

    tokio::time::sleep(Duration::from_millis(60)).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    redis.restart().await;

    let reopened = RedisRoomStore::connect_with_options(&redis.redis_url(), true)
        .await
        .expect("redis store must reconnect");
    let result = reopened
        .reclaim_expired(10)
        .await
        .expect("reclaim must succeed");
    assert_eq!(result.reclaimed, 1);
    assert_eq!(result.cleaned, 0);

    let (next_room, _) = encrypted_room("beta");
    let reused = reopened
        .create(next_room, Duration::from_secs(60))
        .await
        .expect("room must create");
    assert_eq!(reused.room_id, record.room_id);
}

#[tokio::test]
async fn redis_store_create_is_unique_under_concurrency() {
    let (_redis, store) = connected_store().await;

    let mut tasks = Vec::new();
    for index in 0_u64..32 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let (room, _) = encrypted_room(&format!("payload {index}"));
            store
                .create(room, Duration::from_secs(60))
                .await
                .expect("concurrent create must succeed")
                .room_id
        }));
    }

    let mut actual_ids = BTreeSet::new();
    for task in tasks {
        actual_ids.insert(task.await.expect("task must complete"));
    }

    let expected_ids = (0_u64..32)
        .map(|local_id| encode_local_id(3, local_id).expect("id must encode"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);
}

#[tokio::test]
async fn redis_store_persists_allocator_and_clipboard_state_across_restart() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(0, 0), (2, 2)])]).await;

    assert_eq!(
        store
            .free(&public_id(3, 1))
            .await
            .expect("free must succeed"),
        FreeRoomResult::Freed
    );

    let (room_one, _) = encrypted_room("alpha");
    let first = store
        .create(room_one, Duration::from_secs(60))
        .await
        .expect("room must create");
    assert_eq!(first.room_id, public_id(3, 0));
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(1, 2)]
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;
    redis.restart().await;

    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    assert!(
        store
            .get(&first.room_id)
            .await
            .expect("get must succeed")
            .is_some(),
        "clip key should survive restart through AOF"
    );
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(1, 2)]
    );

    let (room_two, _) = encrypted_room("beta");
    let second = store
        .create(room_two, Duration::from_secs(60))
        .await
        .expect("room must create");
    assert_eq!(second.room_id, public_id(3, 1));
}

fn seeded_random_allocator_state() -> Vec<(u8, Vec<(u64, u64)>)> {
    vec![(3, vec![(0, 31)]), (4, vec![(0, 7)])]
}

fn seeded_all_tiers_allocator_state() -> Vec<(u8, Vec<(u64, u64)>)> {
    vec![
        (3, vec![(0, 7)]),
        (4, vec![(0, 7)]),
        (5, vec![(0, 7)]),
        (6, vec![(0, 7)]),
    ]
}

#[derive(Clone)]
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn next_index(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

async fn run_model_equivalence_with_seeded(
    seed: u64,
    steps: usize,
    seeded: Vec<(u8, Vec<(u64, u64)>)>,
) {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&seeded).await;
    let mut reference = build_reference_allocator(&seeded);
    let (room_template, _) = encrypted_room("model");
    let mut rng = Lcg::new(seed);
    let mut active_ids = Vec::new();

    for _ in 0..steps {
        let can_allocate = [3_u8, 4, 5, 6].into_iter().any(|code_len| {
            !reference
                .intervals(code_len)
                .expect("tier must exist")
                .is_empty()
        });
        let should_create = can_allocate && (active_ids.is_empty() || rng.next_u64() % 10 < 6);
        if should_create {
            let expected = reference.allocate().expect("reference must allocate");
            let actual = store
                .create(room_template.clone(), Duration::from_secs(60))
                .await
                .expect("redis create must succeed");
            assert_eq!(actual.room_id, expected.room_id);
            active_ids.push(actual.room_id);
        } else {
            let index = rng.next_index(active_ids.len());
            let room_id = active_ids.swap_remove(index);
            let decoded = decode_room_id(&room_id).expect("active room id must decode");
            let expected = reference
                .free(decoded.code_len, decoded.local_id)
                .expect("reference free must succeed");
            let actual = store.free(&room_id).await.expect("redis free must succeed");
            match (expected, actual) {
                (FreeOutcome::Freed, FreeRoomResult::Freed)
                | (FreeOutcome::AlreadyFree, FreeRoomResult::AlreadyFree) => {}
                mismatch => panic!("reference/redis free mismatch: {mismatch:?}"),
            }
        }

        for code_len in [3_u8, 4, 5, 6] {
            assert_eq!(
                store
                    .free_intervals(code_len)
                    .await
                    .expect("intervals must read"),
                reference
                    .intervals(code_len)
                    .expect("reference tier must exist"),
                "interval mismatch for tier {code_len} at seed {seed}"
            );
        }
    }
}

async fn run_model_equivalence(seed: u64, steps: usize) {
    run_model_equivalence_with_seeded(seed, steps, seeded_random_allocator_state()).await;
}

#[tokio::test]
async fn redis_store_matches_reference_allocator_under_random_sequence_seed_1() {
    run_model_equivalence(1, 200).await;
}

#[tokio::test]
async fn redis_store_matches_reference_allocator_under_random_sequence_seed_2() {
    run_model_equivalence(2, 200).await;
}

#[tokio::test]
async fn redis_store_matches_reference_allocator_under_random_sequence_seed_3() {
    run_model_equivalence(3, 200).await;
}

#[tokio::test]
async fn redis_store_matches_reference_allocator_under_long_random_sequence_seed_11() {
    run_model_equivalence(11, 1_000).await;
}

#[tokio::test]
async fn redis_store_matches_reference_allocator_under_long_random_sequence_seed_12() {
    run_model_equivalence(12, 1_000).await;
}

macro_rules! model_seed_test {
    ($name:ident, $seed:expr, $steps:expr) => {
        #[tokio::test]
        async fn $name() {
            run_model_equivalence($seed, $steps).await;
        }
    };
}

model_seed_test!(
    redis_store_matches_reference_allocator_under_random_sequence_seed_4,
    4,
    200
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_random_sequence_seed_5,
    5,
    200
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_random_sequence_seed_6,
    6,
    200
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_random_sequence_seed_7,
    7,
    200
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_random_sequence_seed_8,
    8,
    200
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_long_random_sequence_seed_13,
    13,
    1_000
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_long_random_sequence_seed_14,
    14,
    1_000
);
model_seed_test!(
    redis_store_matches_reference_allocator_under_long_random_sequence_seed_15,
    15,
    1_000
);

macro_rules! all_tier_model_seed_test {
    ($name:ident, $seed:expr, $steps:expr) => {
        #[tokio::test]
        async fn $name() {
            run_model_equivalence_with_seeded($seed, $steps, seeded_all_tiers_allocator_state())
                .await;
        }
    };
}

all_tier_model_seed_test!(
    redis_store_matches_reference_allocator_across_all_tiers_seed_21,
    21,
    400
);
all_tier_model_seed_test!(
    redis_store_matches_reference_allocator_across_all_tiers_seed_22,
    22,
    400
);
all_tier_model_seed_test!(
    redis_store_matches_reference_allocator_across_all_tiers_seed_23,
    23,
    400
);

#[tokio::test]
async fn redis_store_create_during_outage_errors_without_consuming_an_id() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(0, 1)])]).await;
    redis.stop().await;

    let (room, _) = encrypted_room("outage create");
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        store.create(room, Duration::from_secs(60)),
    )
    .await
    .expect("outage create must resolve")
    .expect_err("create during outage must fail");
    assert!(matches!(error, StoreError::Redis(_)));

    redis.start_existing().await;
    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    let (room, _) = encrypted_room("after outage");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("create after outage must succeed");
    assert_eq!(record.room_id, public_id(3, 0));
}

#[tokio::test]
async fn redis_store_free_during_outage_errors_without_mutating_intervals() {
    let (redis, store) = connected_store().await;
    redis.seed_allocator(&[(3, vec![(0, 0), (2, 2)])]).await;
    redis.stop().await;

    let error = tokio::time::timeout(Duration::from_secs(5), store.free(&public_id(3, 1)))
        .await
        .expect("outage free must resolve")
        .expect_err("free during outage must fail");
    assert!(matches!(error, StoreError::Redis(_)));

    redis.start_existing().await;
    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    assert_eq!(
        store.free_intervals(3).await.expect("intervals must read"),
        vec![(0, 0), (2, 2)]
    );
}

#[tokio::test]
async fn redis_store_update_during_outage_errors_without_mutating_record() {
    let (redis, store) = connected_store().await;
    let (room, created) = encrypted_room("alpha");
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("create must succeed");

    redis.stop().await;

    let next_envelope = encrypt_clipboard(&created.room_key, "beta", record.content_version + 1)
        .expect("next envelope must encrypt");
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        store.update(&record.room_id, next_envelope, Duration::from_secs(60)),
    )
    .await
    .expect("outage update must resolve")
    .expect_err("update during outage must fail");
    assert!(matches!(error, StoreError::Redis(_)));

    redis.start_existing().await;
    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    let persisted = store
        .get(&record.room_id)
        .await
        .expect("get must succeed")
        .expect("record must still exist");
    assert_eq!(persisted.content_version, record.content_version);
}

#[tokio::test]
async fn redis_store_roundtrips_opaque_registration() {
    let (_redis, store) = connected_store().await;
    let (room, _) = encrypted_room("auth roundtrip");
    let expected_auth = room.auth.clone();
    let record = store
        .create(room, Duration::from_secs(60))
        .await
        .expect("create must succeed");

    let fetched = store
        .get_registration(&record.room_id)
        .await
        .expect("registration get must succeed")
        .expect("registration must exist");
    assert_eq!(fetched, expected_auth);
}

#[tokio::test]
async fn redis_store_persists_opaque_server_setup_across_restart() {
    let (redis, store) = connected_store().await;
    let first = store
        .get_or_create_server_setup()
        .await
        .expect("server setup must resolve");
    let first_payload =
        serde_json::to_string(&first).expect("server setup must serialize deterministically");

    redis.restart().await;

    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    let second = store
        .get_or_create_server_setup()
        .await
        .expect("server setup must resolve after restart");
    let second_payload =
        serde_json::to_string(&second).expect("server setup must serialize deterministically");

    assert_eq!(first_payload, second_payload);
}

#[tokio::test]
async fn redis_store_roundtrips_opaque_login_state() {
    let (_redis, store) = connected_store().await;
    let state = secopy::auth::StoredOpaqueLoginState {
        room_id: "abc".to_string(),
        state: {
            let password_file = test_registration("password").password_file;
            let mut rng = OsRng;
            let server_setup = new_server_setup();
            let login_start = opaque_ke::ClientLogin::<secopy::auth::ScpyOpaqueCipherSuite>::start(
                &mut rng,
                b"password",
            )
            .expect("client login must start");
            opaque_ke::ServerLogin::start(
                &mut rng,
                &server_setup,
                Some(password_file),
                login_start.message,
                b"opaque-login-state",
                opaque_ke::ServerLoginParameters::default(),
            )
            .expect("server login must start")
            .state
        },
    };

    store
        .put_login_state("session-1", state.clone(), Duration::from_secs(60))
        .await
        .expect("put login state must succeed");
    let fetched = store
        .take_login_state("session-1")
        .await
        .expect("take login state must succeed")
        .expect("login state must exist");
    assert_eq!(fetched, state);
    assert!(store
        .take_login_state("session-1")
        .await
        .expect("take login state must succeed")
        .is_none());
}

#[tokio::test]
async fn redis_store_persists_opaque_login_state_across_restart() {
    let (redis, store) = connected_store().await;
    let state = secopy::auth::StoredOpaqueLoginState {
        room_id: "opaque-room".to_string(),
        state: {
            let password_file = test_registration("password").password_file;
            let mut rng = OsRng;
            let server_setup = new_server_setup();
            let login_start = opaque_ke::ClientLogin::<secopy::auth::ScpyOpaqueCipherSuite>::start(
                &mut rng,
                b"password",
            )
            .expect("client login must start");
            opaque_ke::ServerLogin::start(
                &mut rng,
                &server_setup,
                Some(password_file),
                login_start.message,
                b"opaque-login-state",
                opaque_ke::ServerLoginParameters::default(),
            )
            .expect("server login must start")
            .state
        },
    };

    store
        .put_login_state("session-restart", state.clone(), Duration::from_secs(60))
        .await
        .expect("put login state must succeed");

    redis.restart().await;

    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    let fetched = store
        .take_login_state("session-restart")
        .await
        .expect("take login state must succeed")
        .expect("login state must survive restart");
    assert_eq!(fetched, state);
}

#[tokio::test]
async fn redis_store_roundtrips_opaque_session() {
    let (_redis, store) = connected_store().await;
    let session = secopy::auth::StoredOpaqueSession {
        room_id: "clip".to_string(),
        created_at_ms: 10,
        expires_at_ms: 20,
    };

    store
        .put_session("session-2", session.clone(), Duration::from_secs(60))
        .await
        .expect("put session must succeed");
    let fetched = store
        .get_session("session-2")
        .await
        .expect("get session must succeed")
        .expect("session must exist");
    assert_eq!(fetched, session);
    store
        .delete_session("session-2")
        .await
        .expect("delete session must succeed");
    assert!(store
        .get_session("session-2")
        .await
        .expect("get session must succeed")
        .is_none());
}

#[tokio::test]
async fn redis_store_persists_opaque_session_across_restart() {
    let (redis, store) = connected_store().await;
    let session = secopy::auth::StoredOpaqueSession {
        room_id: "clip".to_string(),
        created_at_ms: 10,
        expires_at_ms: 20,
    };

    store
        .put_session("session-restart", session.clone(), Duration::from_secs(60))
        .await
        .expect("put session must succeed");

    redis.restart().await;

    let store = RedisRoomStore::connect(&redis.redis_url())
        .await
        .expect("redis store must reconnect");
    let fetched = store
        .get_session("session-restart")
        .await
        .expect("get session must succeed")
        .expect("session must survive restart");
    assert_eq!(fetched, session);
}
