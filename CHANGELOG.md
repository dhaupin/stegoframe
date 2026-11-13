# Changelog

All notable changes to stegoframe are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 2026-11-12 - the Dependabot flow lands (railyard#31)

`.github/dependabot.yml` now carries the family flow: a weekly (Monday) pass, grouped minor/patch updates in one pull request, majors alone, and the `github-actions` ecosystem so the SHA-pinned refs move without a hand-edit. stegoframe declares no npm dependencies, so the `github-actions` ecosystem alone applies. The shape is proved and guarded on the parent (`dhaupin/creadev` PR #38; `dhaupin/railyard#31`). No version bump.

## [1.0.0] - 2026-11-12

The first versioned release. stegoframe is an identity-agnostic steganographic transport middleware: it encrypts an arbitrary payload (AES-GCM-256, PBKDF2-SHA256 at 100k iterations) and hides it inside an image carrier - SVG vector art or LSB PNG noise - then delivers the carrier through Supabase Realtime. The server sees only encrypted carrier images; without the shared passphrase a carrier is indistinguishable from decorative art.

### Added

- **Two carrier modes, one encryption layer.** SVG (`<brn:secret>` base64 attribute) and LSB (least-significant red-channel bits, MSB-first, x-major). Mode is fixed per room and shared through the room URL; it is an aesthetic choice, not a security choice.
- **The `BRN:ENC:` packet, shared with Vant.** `"BRN:ENC:" + hex(salt):hex(iv):hex(authTag):hex(ciphertext)`, the same wire format as Vant's `lib/stego.js` (see [docs/lsb-spec.md](./docs/lsb-spec.md)). A carrier whose payload does not start with the `BRN:` magic reads as empty, never a garbage packet; a wrong passphrase is an AES-GCM auth failure, also silent.
- **Passphrase-derived room IDs.** The room ID is `SHA-256(passphrase)` truncated to 6 characters, so the room URL is only guessable by someone who knows the passphrase.
- **Client-enforced room lifecycle.** Empty rooms purge after 24 hours, active rooms expire after 7 days, and leaving a room hard-deletes its messages and record. Client limits: 2,000-character messages, 500 messages per room, ~500 KB carriers, 1 message per second.
- **The Cloudflare Pages worker and the Supabase schema.** `_worker.js` injects `SUPA_URL`/`SUPA_ANON` at request time; `migrations/` carries the fresh-setup SQL.

### Security

- **The passphrase never leaves the client.** The server (Supabase) only ever stores encrypted carrier images.
- **No identity verification, no forward secrecy.** Any participant with the passphrase can read and post to a room, and one PBKDF2-derived key serves every message in a session. Documented as boundaries, not bugs ([AGENTS.md](./AGENTS.md)).
