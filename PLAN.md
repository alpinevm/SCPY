# scpy.app Plan

## Product Definition

Build a fully open-source, end-to-end encrypted live clipboard service with very short URLs.

Core requirements:

- Very short room URLs.
- End-to-end encryption by default.
- The server must never see plaintext clipboard contents or raw room passwords.
- Live clipboard sync between connected clients.
- One deployable Rust backend that serves the API, SSE transport, and web UI shell.
- Strong SEO for public pages without leaking private room data.

Initial scope:

- Text clipboard only.
- Anonymous rooms.
- One current clipboard value per room.
- Single server deployment.
- Open source from day one.

Out of scope for v1:

- File uploads.
- Account system.
- Multi-region or multi-node clustering.
- Perfect anti-rollback guarantees against a malicious server.
- PAKE or OPAQUE-based password-authenticated write control.

## Brand and Routing

Public product name:

- `scpy.app`

Recommended route shape:

- `https://scpy.app/c/2A7`

ID strategy:

- Allocated, not user chosen.
- Minimum length: 3 characters.
- Maximum length: 6 characters.
- Human-safe Base56 alphabet.
- Tiers are exhausted in order: `3 -> 4 -> 5 -> 6`.
- Concrete allocator spec lives in `docs/redis_allocator.md`.

## Rendering and SEO

Keep Leptos and keep SSR.

Decision:

- Use Leptos with SSR + hydration via `leptos_axum`.
- Use SSR for the landing page and any future public marketing or docs pages.
- Use SSR for the room shell only, not room contents.
- Mark private room routes as `noindex, nofollow`.

Why this is the right cut:

- SSR gives you crawlable HTML and metadata for public pages.
- The encrypted clipboard flow still runs client-side after hydration.
- E2EE and SSR are not in conflict as long as secrets and ciphertext decryption stay in the browser.
- Room URLs should not be indexed anyway, so a noindex SSR shell is the correct privacy posture.

Practical rule:

- Public routes are SEO-visible.
- Private room routes are crawl-resistant and content-blind.

## Recommended Stack

- Language/runtime: Rust stable + Tokio.
- HTTP/router/SSE server: Axum.
- Frontend: Leptos with SSR + hydration via `leptos_axum`.
- Client-side crypto: Rust code compiled to WASM.
- KDF: `argon2` crate using Argon2id in the browser.
- Key splitting: `hkdf` + SHA-256.
- Authenticated encryption: `chacha20poly1305` crate using XChaCha20-Poly1305.
- State store: Redis for encrypted room metadata and ciphertext only.
- Realtime fanout: Axum SSE + Tokio broadcast channels.
- Middleware/ops: `tower-http`, `tracing`, `tracing-subscriber`.

Notes:

- Leptos stays because SSR is useful here, not harmful.
- The web server you wanted earlier is `axum`.
- The browser becomes the cryptographic trust boundary.

## Security Model

Use an E2EE, zero-knowledge server model for v1.

Meaning:

- The browser derives keys locally.
- The browser encrypts and decrypts clipboard payloads locally.
- The server stores and relays ciphertext only.
- The server never receives plaintext room passwords or plaintext clipboard contents.

What this protects:

- Server compromise does not reveal plaintext clipboard contents.
- Open-sourcing the server does not weaken confidentiality if the client crypto is implemented correctly.
- Operators can inspect traffic volume and metadata, but not secret room contents.

What this does not solve completely:

- A malicious server can still drop, delay, or replay ciphertext.
- A malicious server can still DoS a room.
- Strong write authorization without trusting the server is harder than encryption alone.

So the honest v1 position is:

- Confidentiality is zero-knowledge.
- Integrity is client-validated.
- Availability and rollback resistance are only partially mitigated in v1.

## E2EE Room Flow

### Room Creation

When a room is created:

- Generate a random room ID.
- Generate a random room data key in the browser.
- Generate a random KDF salt in the browser.
- Derive a wrapping key from the user password with Argon2id.
- Wrap the room data key locally with the wrapping key.
- Encrypt the clipboard payload locally with the room data key.
- Upload only:
  - room ID
  - KDF salt and params
  - wrapped room key
  - ciphertext envelope
  - public metadata such as version and timestamps

### Room Open

When a user opens a room:

- Fetch public room metadata and the latest ciphertext envelope.
- Derive the wrapping key locally from the password.
- Unwrap the room data key locally.
- Decrypt the ciphertext locally.
- Keep plaintext only in browser memory.

### Room Sync

For live updates:

- Clients encrypt updates locally before sending them.
- The SSE channel carries encrypted envelopes only.
- The server persists and rebroadcasts encrypted envelopes blindly.
- Clients verify versioning and authenticated encryption before accepting an update.

## Authorization and Abuse Model

This is the hardest part of a true zero-knowledge design.

V1 posture:

- Use short random but unguessable room IDs.
- Apply rate limits to room creation and room writes.
- Let clients reject malformed or undecryptable updates.
- Treat write authorization as capability-by-knowledge plus rate limiting, not strong server-side password auth.

Important consequence:

- The server will not be able to verify "correct password" without a more advanced protocol.
- If we want strong password-authenticated writes without trusting the server, we should plan OPAQUE or another PAKE later.

## Data Model

Redis keys:

- `room:{id}:meta`
- `room:{id}:content`

Suggested metadata fields:

- `kdf_salt`
- `kdf_memory_cost`
- `kdf_time_cost`
- `kdf_parallelism`
- `wrapped_room_key`
- `wrapped_room_key_nonce`
- `content_nonce`
- `content_version`
- `content_len`
- `created_at`
- `updated_at`
- `expires_at`

Content value:

- The current encrypted clipboard envelope as a Redis string.

Server-side in-memory state:

- Per-room Tokio broadcast sender for ciphertext fanout.

What the server must not store:

- Plaintext clipboard contents.
- Plaintext room passwords.
- Server-side decrypted room keys.

## API and Routing Shape

Browser routes:

- `GET /`
- `GET /r/:room_id`

HTTP endpoints:

- `POST /api/rooms`
- `GET /api/rooms/:room_id`
- `POST /api/rooms/:room_id/clipboard`

Realtime endpoint:

- `GET /api/rooms/:room_id/events`

Implementation note:

- Use ordinary JSON endpoints and an SSE route for encrypted room traffic.
- Avoid server-side room business logic that assumes access to plaintext.
- SSR should render only the page shell and public metadata.

## Clipboard Envelope

Each encrypted update should carry:

- `version`
- `nonce`
- `ciphertext`
- `updated_at`
- `client_id`
- optional `previous_version`

The browser should:

- Reject undecryptable payloads.
- Reject obviously stale versions when possible.
- Warn on potential rollback or replay.

## Clipboard Semantics

V1 behavior:

- Text only.
- Last-writer-wins.
- No edit history.
- No merge logic.
- Presence is optional.

Recommended limits for v1:

- Soft limit: 256 KiB per clipboard payload.
- Hard ceiling after validation: 512 KiB.

These limits are conservative and still appropriate even with Redis storing ciphertext.

## Delivery Plan

### Phase 0: Brand and Shell

- Rebrand the scaffold to `scpy.app`.
- Keep Leptos SSR + hydration.
- Mark room pages as `noindex`.
- Preserve a strong landing page for SEO and product clarity.

### Phase 1: Client Crypto

- Add browser-side Argon2id key derivation.
- Add browser-side room key generation and wrapping.
- Add browser-side envelope encryption and decryption.
- Add test vectors for encryption and unwrap flows.

### Phase 2: Blind Persistence

- Implement `POST /api/rooms`.
- Implement `GET /api/rooms/:room_id`.
- Implement blind ciphertext storage in Redis.
- Ensure the server never logs ciphertext payload bodies.

### Phase 3: Blind Realtime Sync

- Implement room SSE fanout.
- Broadcast encrypted envelopes only.
- Handle reconnect and snapshot fetch.
- Add client-side stale update detection.

### Phase 4: Hardening

- Add rate limits for creation and writes.
- Add request size limits.
- Add CSP and security headers.
- Add robots/noindex rules for private routes.
- Add structured logs that avoid leaking encrypted payloads.

### Phase 5: Deployment

- Deploy to Railway.
- Add the `scpy.app` custom domain.
- Configure Redis and environment variables.
- Document the open-source deployment flow.

## Testing Plan

- Unit tests for Argon2id config, HKDF key splitting, wrapping, and ciphertext round trips.
- Browser/WASM tests for room creation and room open flows.
- Integration tests for blind room create, fetch, and ciphertext update APIs.
- SSE tests for encrypted multi-client propagation.
- Tests for noindex behavior on room pages.
- Load tests with many small writes and occasional large encrypted payloads.

## Open Decisions

- Password only, or password plus a capability token in the URL fragment?
- Do rooms expire automatically?
- Is text only acceptable for v1?
- Is read-only mode needed?
- Do we want lightweight rollback warnings only, or a stronger append-only event chain later?

## Redis Fit Check

Redis is still a good fit for the encrypted current-value payload in v1.

What matters:

- Redis strings can store values up to 512 MB.
- Hundreds of KiB to around 1 MiB is technically fine for plain `GET` and `SET`.
- The real cost is still network transfer, memory pressure, and hot-key latency.

Practical guidance:

- Store the latest ciphertext envelope in Redis.
- Keep payloads capped.
- Avoid using Redis as long-term history storage.

## Reference Links

- Leptos getting started: https://book.leptos.dev/getting_started/
- Leptos book: https://book.leptos.dev/
- Axum docs: https://docs.rs/axum/latest/axum/
- Argon2 crate docs: https://docs.rs/argon2/latest/argon2/
- Redis string docs: https://redis.io/docs/latest/develop/data-types/strings/
