-- RLS applied to several tables at once in PL/pgSQL loops (three styles used across the fleet).
create table if not exists public.loop_members (id uuid primary key, business_id uuid);
create table if not exists public.loop_readonly (id uuid primary key, business_id uuid);
create table if not exists public.loop_declared (id uuid primary key);
create table if not exists public.loop_foreach (id uuid primary key);
create table if not exists public.loop_forgotten (id uuid primary key);

do $$
declare t text;
begin
  for t in select unnest(array['loop_members'])
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format($p$create policy "members access own rows" on public.%I for all
      using (business_id in (select my_business_ids()))$p$, t);
  end loop;
  for t in select unnest(array['loop_readonly'])
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format($p$create policy "members read own rows" on public.%I for select
      using (business_id in (select my_business_ids()))$p$, t);
  end loop;
end $$;

do $$
declare
  t text;
  setup_tables text[] := array['loop_declared'];
begin
  foreach t in array setup_tables loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $$;

do $$
declare t text;
begin
  foreach t in array array['loop_foreach'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('create policy "open read" on public.%I for select using (true)', t);
  end loop;
end $$;
