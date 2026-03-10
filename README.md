# Stegoframe
An experimental platform to send and receive data payloads using raster or svg images as the carrier. Built for humans, and machines.

https://stegoframe.dhaupin.workers.dev

# Supabase Init SQL
```sql
create table messages (
  id         uuid primary key default gen_random_uuid(),
  room_id    text not null,
  carrier    text not null,
  mode       text not null default 'svg',
  sender_id  text not null,
  ts         timestamptz not null default now()
);

create index on messages(room_id, ts);

create policy "read messages"
  on messages for select
  using (true);

create policy "insert messages"
  on messages for insert
  with check (true);

create policy "delete own messages"
  on messages for delete
  using (true);
```
