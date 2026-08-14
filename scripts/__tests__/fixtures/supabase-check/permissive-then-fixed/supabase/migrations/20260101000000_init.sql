create table public.orders (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null
);
alter table public.orders enable row level security;
create policy "anyone can read" on public.orders for select using (true);
