# Stegoframe - TASKS

> Rolling log. The product contract lives in [README.md](../README.md) (human-facing) and [AGENTS.md](../AGENTS.md) (agent-facing); this file is the memory of what changed and why.
>
> Session log format: `- [DATETIME] note` (newest at top). Struck items are done.

## What this is

stegoframe is an identity-agnostic steganographic transport middleware. It encrypts a payload (AES-GCM-256, PBKDF2-SHA256 at 100k iterations) and hides it inside an image carrier - SVG vector art or LSB PNG noise - then delivers the carrier through Supabase Realtime. The server sees only encrypted carrier images.

## Boundaries (documented, not bugs)

- No identity verification: any participant with the passphrase can read and post.
- No forward secrecy: one PBKDF2-derived key serves every message in a session.
- No server-side TTL or size enforcement: the room lifecycle and the client limits are client-enforced.

## Log

### 2026-11-13 - the staging fast-forward sync lands (the family plumbing)

- **Added `.github/workflows/staging-ff-sync.yml`** - the family's required sync step, vendored byte-identical from the coreforge canon (44 lines). On every push to `main` it fast-forwards `staging` with a fast-forward-only refspec (never a merge, never a force-push); the `delete` trigger recreates `staging` if the `--delete-branch` trap removes it. stegoframe had `main` + `staging` but carried no workflow at all, so the mirror was manual.
- **No version bump** (1.0.0 = 1.0.0); a plumbing pass.

### 2026-11-12 - the memory convention lands (railyard#31)

- **Added `CHANGELOG.md`** (Keep a Changelog) with the 1.0.0 section reconstructed from the tree and the first `[Unreleased]` entry for the Dependabot flow.
- **Added this `labs/` memory** so stegoframe carries the family convention (CHANGELOG + labs log) that every sibling repo holds. Previously it had neither.
- **`.github/dependabot.yml`** lands with the family flow (weekly Monday, grouped minor/patch, `github-actions` ecosystem only - stegoframe declares no npm dependencies).
- **No version bump** (1.0.0 = 1.0.0); a memory-convention pass.
