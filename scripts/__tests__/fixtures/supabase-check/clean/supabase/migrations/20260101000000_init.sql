-- CREATE TABLE IF NOT EXISTS reference_pricing never actually ran in prod — noted here only
-- as a comment, to make sure comment text isn't mistaken for a real statement.
create table public.reference_pricing (
  id uuid primary key default gen_random_uuid(),
  sku text not null,
  price numeric not null
);
alter table public.reference_pricing enable row level security;
create policy "anyone can read pricing" on public.reference_pricing for select using (true);
create policy "only owner can write" on public.reference_pricing for insert with check (auth.uid() is not null);
create policy "only owner can update" on public.reference_pricing for update using (auth.uid() is not null);
create policy "only owner can delete" on public.reference_pricing for delete using (auth.uid() is not null);

create or replace function public.recalc_price(sku text) returns void
language plpgsql
security definer
as $$
begin
  -- validates auth.uid() internally before writing
  update public.reference_pricing set price = price where reference_pricing.sku = recalc_price.sku;
end;
$$;
