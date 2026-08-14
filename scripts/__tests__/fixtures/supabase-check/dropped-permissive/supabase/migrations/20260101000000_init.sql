create table public.legacy_feed (
  id uuid primary key default gen_random_uuid()
);
alter table public.legacy_feed enable row level security;
create policy "public read" on public.legacy_feed for select using (true);
