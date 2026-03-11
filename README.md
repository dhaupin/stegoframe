# Stegoframe

A steganographic transport middleware. Payloads are encrypted with AES-GCM-256 and hidden inside image carriers — either SVG vector art or PNG pixel noise. The carriers are indistinguishable from decorative images to anyone without the shared passphrase. Supabase Realtime handles cross-device delivery. The passphrase never leaves the client.

**Live:** `https://stegoframe.pages.dev`

---

## How it works

```
plaintext → AES-GCM-256 encrypt → binary payload
         → pack into image carrier (SVG or LSB PNG)
         → post carrier data URL to Supabase room
         → other participants receive via Realtime
         → decode carrier → decrypt → plaintext
```

The server (Supabase) only ever sees encrypted carrier images. Without the passphrase they are computationally indistinguishable from noise or abstract art. The room ID is public. The passphrase is not.

### Encoding modes

| Mode | Carrier looks like | Payload location |
|------|--------------------|-----------------|
| SVG  | Abstract gradient art | `<desc data-p="...">` base64 attribute |
| LSB  | Pixel noise / static | Least-significant bits of red channel pixels |

Both modes use the same encryption layer. Mode is fixed per room and shared via the URL query string.

### Binary framing

All payloads are wrapped in an 8-byte frame header before encryption:

```
[0-2]  MAGIC   0x534746 ("SGF")
[3]    VERSION 0x02
[4-7]  LENGTH  uint32 big-endian (payload byte count)
[8+]   PAYLOAD encrypted bytes
```

Magic + version mismatch = null decode. Wrong passphrase = AES-GCM auth failure = null decode. Both cases are silent — the carrier just appears to contain no valid data.

---

## Rooms

Rooms are identified by a short random alphanumeric code generated at creation. The room code and encoding mode are shared in the URL:

```
https://stegoframe.pages.dev/?room=abc123&mode=svg
```

The passphrase is **never** in the URL. Joining participants enter it manually after opening the link. The room remains accessible as long as messages exist in Supabase. When a participant leaves, all messages for that room are hard-deleted from the database for all participants.

### Session identity

Each browser tab generates a random UUID on first open, stored in `sessionStorage`. This is the `sender_id` attached to every message. It determines "you" vs "them" in the UI, and gates the delete button to your own messages only. The session ID is tab-scoped — a new tab is a new participant identity.

---

## Security properties

- **Passphrase never transmitted.** Key derivation (PBKDF2-SHA256, 100,000 iterations) and all encryption/decryption happen client-side only.
- **Supabase sees ciphertext only.** Every `carrier` column value is an encrypted data URL. No plaintext, no metadata about message content.
- **Wrong passphrase = silent failure.** AES-GCM authentication tag mismatch returns null. No error leaks information about whether a payload exists.
- **Room wipe on leave.** Leaving a room hard-deletes all rows for that `room_id` from Supabase. Realtime DELETE events propagate to all connected participants.
- **No auth layer.** The anon Supabase key is public by design. RLS policies permit all reads and inserts. Delete is open (`using (true)`) — enforcement is application-level only. For production use, consider adding a room token or signed delete endpoint.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Hosting | Cloudflare Pages (static) |
| Realtime DB | Supabase (Postgres + Realtime) |
| Encryption | Web Crypto API — AES-GCM-256, PBKDF2-SHA256 |
| UI | React 18 (UMD, no build step) + Babel standalone |
| Fonts | DM Mono, Syne (Google Fonts) |

No build tools. No bundler. One HTML file.

---

## Supabase setup

### 1. Create project

Go to [supabase.com](https://supabase.com), create a new project.

### 2. Run SQL

In **Database → SQL Editor**, run the following in full:

```sql
-- Messages table
create table messages (
  id         uuid primary key default gen_random_uuid(),
  room_id    text not null,
  carrier    text not null,
  mode       text not null default 'svg',
  sender_id  text not null,
  ts         timestamptz not null default now()
);

-- Index for efficient room queries
create index on messages(room_id, ts);

-- Enable RLS (required — without this all queries return empty)
alter table messages enable row level security;

-- Allow anon key to read all messages in any room
create policy "read messages"
  on messages for select
  using (true);

-- Allow anon key to insert messages
create policy "insert messages"
  on messages for insert
  with check (true);

-- Allow deletion (ownership enforced in app, not DB)
create policy "delete own messages"
  on messages for delete
  using (true);

-- Required for Realtime DELETE events to include the deleted row's id.
-- Without this, payload.old is empty and remote deletes won't sync.
alter table messages replica identity full;
```

### 3. Enable Realtime

In **Database → Replication**, enable Realtime for the `messages` table.

### 4. Get credentials

In **Project Settings → API**, copy:
- Project URL
- `anon` public key

Paste both into `index.html`:

```js
const SUPA_URL  = "https://your-project.supabase.co";
const SUPA_ANON = "your-anon-key";
```

### 5. Deploy

Push `index.html` to a GitHub repo. Connect to Cloudflare Pages with no build command and no output directory. It deploys in ~30 seconds.

---

## Human usage

1. Open the app, enter a passphrase and encoding mode, create a room
2. Copy the room URL (⎗ button), share it with the other party out-of-band
3. They open the URL, enter the same passphrase, join the room
4. Type messages and send — each message is encrypted into a carrier image and posted to Supabase
5. The other party sees the carrier thumbnail and decoded plaintext in real time
6. To receive a carrier from outside the app (e.g. a saved file or copied data URL), use the ⊕ file picker or ⌗ paste bar
7. When done, leave the room — this wipes all messages from the database for all participants

---

## Machine / AI usage

See [`AGENTS.md`](./AGENTS.md) for the full integration reference.

Brief overview: AI systems interact with Stegoframe as a transport layer, not a chat UI. The codec is the primitive. The Supabase room is the channel. The passphrase is the shared secret established out-of-band between participating systems.

---

## Codec frame reference

```
Encryption:     AES-GCM-256
Key derivation: PBKDF2-SHA256, 100,000 iterations, 16-byte random salt
IV:             12 bytes random per message
Frame header:   8 bytes (magic 3 + version 1 + length 4)
Magic:          0x534746 ("SGF")
Version:        0x02
```

SVG carrier extraction:
```js
const m = svgText.match(/data-p="([A-Za-z0-9+/=]+)"/);
const packed = base64ToBytes(m[1]);  // 8-byte header + ciphertext
```

LSB carrier extraction:
```js
// Read R-channel LSBs sequentially from pixel data
// First 64 bits = 8-byte frame header
// Remaining LENGTH*8 bits = ciphertext bytes
```

---

## File structure

```
index.html   — entire application (codec + UI + Supabase client)
README.md    — this file
AGENTS.md    — AI/agent integration reference
```
