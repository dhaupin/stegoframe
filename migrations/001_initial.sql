-- Stegoframe Migration: Initial Schema
-- Run this in Supabase SQL Editor to set up a fresh database
-- ──────────────────────────────────────────────────────────────────────────────

-- Enable required extensions
create extension if not exists "uuid-ossp";

-- ── Rooms table ───────────────────────────────────────────────────────────────
-- Tracks room existence and TTL (7-day expiry)
create table if not exists rooms (
  id          text        primary key,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null
);

-- Index for expiry queries (if needed)
create index if not exists idx_rooms_expires_at on rooms(expires_at);

-- ── Messages table ────────────────────────────────────────────────────────────
-- Encrypted carrier images + metadata
create table if not exists messages (
  id           uuid        primary key default gen_random_uuid(),
  room_id      text        not null references rooms(id) on delete cascade,
  carrier      text        not null,  -- encrypted data URL (opaque to server)
  mode         text        not null default 'svg',  -- 'svg' or 'lsb'
  sender_id    text        not null,  -- ephemeral session UUID
  display_name text,                  -- plaintext username (not sensitive)
  ts           timestamptz not null default now()
);

-- Index for efficient room queries
create index if not exists idx_messages_room_ts on messages(room_id, ts);

-- ── Row Level Security ────────────────────────────────────────────────────────
-- Allow anon access (Supabase anon key is public by design)
alter table rooms    enable row level security;
alter table messages enable row level security;

-- Rooms policies
create policy if not exists "rooms read"   on rooms for select using (true);
create policy if not exists "rooms insert" on rooms for insert with check (true);
create policy if not exists "rooms delete" on rooms for delete using (true);

-- Messages policies
create policy if not exists "messages read"   on messages for select using (true);
create policy if not exists "messages insert" on messages for insert with check (true);
create policy if not exists "messages delete" on messages for delete using (true);

-- Required for Realtime DELETE events to include the deleted row's id.
-- Without this, payload.old is empty and remote deletes won't propagate.
alter table messages replica identity full;

-- ── pg_cron: Auto-purge expired rooms ────────────────────────────────────────
-- Enable extension (if not already enabled)
create extension if not exists pg_cron;

-- Schedule daily cleanup at 03:00 UTC
-- The ON DELETE CASCADE on messages.room_id handles message cleanup automatically.
select cron.schedule(
  'purge-expired-rooms',
  '0 3 * * *',
  $$delete from rooms where expires_at < now()$$
);

-- ── Enable Realtime ───────────────────────────────────────────────────────────
-- In Supabase Dashboard: Database → Replication → Enable Realtime for 'messages' table
-- Or run: alter publication supabase_realtime add table messages;

-- ── Done ──────────────────────────────────────────────────────────────────────
-- Your Stegoframe database is now ready!
