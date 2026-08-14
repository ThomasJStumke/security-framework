-- Replace the overly-broad read policy with an owner-scoped one.
drop policy "anyone can read" on public.orders;
create policy "owner can read" on public.orders for select using (auth.uid() = owner);
