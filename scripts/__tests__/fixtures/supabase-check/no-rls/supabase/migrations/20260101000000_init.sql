create table public.widgets (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
