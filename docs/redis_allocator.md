# Redis Allocator Spec

## Goals

- Use the shortest possible clipboard codes first.
- Allocate 3-character codes to exhaustion before allocating any 4-character codes.
- Allocate 4-character codes to exhaustion before allocating any 5-character codes.
- Allocate 5-character codes to exhaustion before allocating any 6-character codes.
- Keep allocator state as first-class Redis state.
- Never rebuild allocator state by scanning all live clipboards.
- Make Redis Lua the only allocator mutation boundary.
- Keep the design compatible with Redis AOF restoring current truth.

## Encoding

### Alphabet

Use fixed-width Base56 to avoid visually confusing characters:

- `23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz`

### Tier Order

Allocation order is strict and global:

1. 3-character tier
2. 4-character tier
3. 5-character tier
4. 6-character tier

A code never changes tiers. A freed 3-character code returns only to the 3-character tier.

### Tier Capacities

- 3 chars: `56^3 = 175,616`
- 4 chars: `56^4 = 9,834,496`
- 5 chars: `56^5 = 550,731,776`
- 6 chars: `56^6 = 30,840,979,456`

### Local ID Mapping

Each tier has its own zero-based local integer ID space:

- 3-char tier: `0..175615`
- 4-char tier: `0..9834495`
- 5-char tier: `0..550731775`
- 6-char tier: `0..30840979455`

Encoding and decoding are fixed-width within the tier:

- local ID `0` in the 3-char tier encodes as `222`
- local ID `0` in the 4-char tier encodes as `2222`

The allocator stores and reasons about:

- `code`
- `code_len`
- `local_id`

That is enough to free deterministically.

## Redis Keys

All keys are prefixed with `scpy:`.

### Clipboard State

- `scpy:clip:{code}`

Type:

- `STRING`

Value:

- JSON blob containing the full persisted clipboard record.

Suggested JSON shape:

```json
{
  "schema_version": 1,
  "code": "2A7",
  "code_len": 3,
  "local_id": 657,
  "created_at_ms": 1760000000000,
  "updated_at_ms": 1760000000000,
  "expires_at_ms": 1760003600000,
  "content_version": 1,
  "meta": {
    "kdf_salt_b64": "...",
    "kdf_memory_cost_kib": 19456,
    "kdf_time_cost": 2,
    "kdf_parallelism": 1,
    "wrapped_room_key_b64": "...",
    "wrapped_room_key_nonce_b64": "..."
  },
  "envelope": {
    "version": 1,
    "nonce_b64": "...",
    "ciphertext_b64": "..."
  }
}
```

TTL:

- The key gets a Redis TTL.
- `expires_at_ms` is also stored inside the JSON so reclaim logic can reason about expiration semantics without trusting physical expiry timing.

### Allocator Interval State

Per tier:

- `scpy:alloc:{len}:starts`
- `scpy:alloc:{len}:ends`

Types:

- `scpy:alloc:{len}:starts` is a `ZSET`
- `scpy:alloc:{len}:ends` is a `HASH`

Representation:

- `starts` stores interval starts as both score and member.
- `ends` maps interval start -> interval end.

Example for the 3-char tier:

- `ZADD scpy:alloc:3:starts 0 "0"`
- `HSET scpy:alloc:3:ends "0" "175615"`

This represents one free interval: `[0, 175615]`

### Optional Expiry Index

If reclaim should happen fully inside Redis rather than from an external maintenance signal, add:

- `scpy:clip:expiring`

Type:

- `ZSET`

Representation:

- score = `expires_at_ms`
- member = `code`

This key is optional in the architecture. It is not required if reclaim is driven by another durable signal.

### Initialization Sentinel

- `scpy:alloc:init:v1`

Type:

- `STRING`

Purpose:

- Guards one-time allocator initialization.

## Allocator Invariants

For every tier:

- Intervals are inclusive.
- Intervals are non-overlapping.
- Intervals are non-adjacent.
- Each interval satisfies `start <= end`.
- The union of all free intervals is exactly the currently free local ID set for that tier.

Cross-tier invariants:

- A code exists in exactly one tier.
- Allocation order always probes tiers in `3 -> 4 -> 5 -> 6`.
- Free never moves a code across tiers.

## Lua Script Contracts

These scripts are the only mutation boundary for allocator state.

### `alloc_init.lua`

Purpose:

- Seed allocator state if not already initialized.

Inputs:

- `ARGV[1] = prefix` (`scpy`)

Behavior:

- If `scpy:alloc:init:v1` exists, no-op.
- Otherwise create one full free interval for each tier:
  - 3: `[0, 175615]`
  - 4: `[0, 9834495]`
  - 5: `[0, 550731775]`
  - 6: `[0, 30840979455]`
- Set `scpy:alloc:init:v1 = 1`

Return:

- `["ok", "initialized"]`
- `["ok", "already_initialized"]`

### `clip_create.lua`

Purpose:

- Allocate the shortest available code and create the persisted clipboard record atomically.

Inputs:

- `ARGV[1] = prefix`
- `ARGV[2] = now_ms`
- `ARGV[3] = ttl_ms`
- `ARGV[4] = content_version`
- `ARGV[5] = clipboard_json_without_allocator_fields`
- `ARGV[6] = use_expiry_index` (`0` or `1`)

Behavior:

1. Probe tiers in order `3, 4, 5, 6`
2. Read the smallest free interval from the first non-empty tier
3. Allocate the interval start as `local_id`
4. Shrink or remove that free interval
5. Encode `local_id` into fixed-width Base56 `code`
6. Build the final persisted clipboard JSON by adding:
   - `code`
   - `code_len`
   - `local_id`
   - `created_at_ms`
   - `updated_at_ms`
   - `expires_at_ms = now_ms + ttl_ms`
   - `content_version`
7. `SET scpy:clip:{code} <json> PX <ttl_ms>`
8. If enabled, `ZADD scpy:clip:expiring expires_at_ms code`

Return:

- `["ok", code, code_len, local_id, expires_at_ms]`
- `["err", "allocator_exhausted"]`

### `clip_write.lua`

Purpose:

- Replace the encrypted clipboard payload and refresh expiration atomically.

Inputs:

- `ARGV[1] = prefix`
- `ARGV[2] = code`
- `ARGV[3] = now_ms`
- `ARGV[4] = ttl_ms`
- `ARGV[5] = expected_content_version`
- `ARGV[6] = next_content_version`
- `ARGV[7] = next_meta_json`
- `ARGV[8] = next_envelope_json`
- `ARGV[9] = use_expiry_index` (`0` or `1`)

Behavior:

1. Load `scpy:clip:{code}`
2. If missing, return not found
3. Decode stored JSON
4. If `content_version != expected_content_version`, return version conflict
5. Replace:
   - `meta`
   - `envelope`
   - `content_version`
   - `updated_at_ms`
   - `expires_at_ms = now_ms + ttl_ms`
6. Write the full JSON back
7. Refresh Redis TTL
8. If enabled, update `scpy:clip:expiring`

Return:

- `["ok", next_content_version, expires_at_ms]`
- `["err", "not_found"]`
- `["err", "version_conflict", current_content_version]`

### `clip_refresh.lua`

Purpose:

- Extend clipboard lifetime without changing encrypted payload.

Inputs:

- `ARGV[1] = prefix`
- `ARGV[2] = code`
- `ARGV[3] = now_ms`
- `ARGV[4] = ttl_ms`
- `ARGV[5] = use_expiry_index` (`0` or `1`)

Behavior:

1. Load `scpy:clip:{code}`
2. If missing, return not found
3. Update:
   - `updated_at_ms`
   - `expires_at_ms = now_ms + ttl_ms`
4. Write the full JSON back
5. Refresh Redis TTL
6. If enabled, update `scpy:clip:expiring`

Return:

- `["ok", expires_at_ms]`
- `["err", "not_found"]`

### `clip_free.lua`

Purpose:

- Delete clipboard state if present and merge its code back into the allocator atomically.

Inputs:

- `ARGV[1] = prefix`
- `ARGV[2] = code`
- `ARGV[3] = code_len`
- `ARGV[4] = local_id`
- `ARGV[5] = use_expiry_index` (`0` or `1`)

Behavior:

1. Determine whether `local_id` is already covered by an existing free interval
2. If already free, no-op and return `already_free`
3. Delete `scpy:clip:{code}` if it exists
4. Remove `code` from `scpy:clip:expiring` if enabled
5. Check for adjacent left interval where `left_end + 1 == local_id`
6. Check for adjacent right interval where `right_start == local_id + 1`
7. Merge one of:
   - no neighbor -> add `[local_id, local_id]`
   - left only -> extend left to `local_id`
   - right only -> replace right with `[local_id, right_end]`
   - both -> merge into `[left_start, right_end]`

Return:

- `["ok", "freed"]`
- `["ok", "already_free"]`

Idempotency rule:

- Calling `clip_free.lua` twice for the same `(code_len, local_id)` must be safe.

### `clip_reap_expired.lua`

Purpose:

- Optional Redis-side maintenance pass that frees expired clipboards without depending on external AOF parsing.

Inputs:

- `ARGV[1] = prefix`
- `ARGV[2] = now_ms`
- `ARGV[3] = limit`

Behavior:

1. Read up to `limit` expired codes from `scpy:clip:expiring`
2. For each code:
   - load clipboard JSON
   - if missing, remove from `scpy:clip:expiring`
   - if `expires_at_ms <= now_ms`, call the same internal free logic as `clip_free.lua`

Return:

- `["ok", reclaimed_count]`

## Allocation Policy

The allocator is intentionally simple:

- Always allocate the lowest available local ID from the shortest non-empty tier.
- Always free back into the exact tier that originally owned the code.
- Never compact across tiers.

This guarantees:

- 3-character codes are used fully before 4-character codes appear.
- 4-character codes are used fully before 5-character codes appear.
- 5-character codes are used fully before 6-character codes appear.

## Failure Model

What this design assumes:

- Single primary Redis instance.
- Redis AOF restores current allocator state and current clipboard state.
- Lua script execution is atomic within Redis.

What this design does not assume:

- Permanent AOF history as an event log.
- Exact wall-clock expiry timing.
- Rebuilding allocator intervals from all currently live clipboards.

## Implementation Notes

- Keep the persisted clipboard record self-contained in one Redis string.
- Parse and rewrite that JSON only inside Lua for allocator-tied mutations.
- The Rust application layer should treat the Lua return values as the source of truth for:
  - allocated code
  - code tier
  - local ID
  - expiration results
- If `appendfsync everysec` is used, the last second of acknowledged mutations may be lost on crash. That is a Redis durability setting, not an allocator design flaw.
