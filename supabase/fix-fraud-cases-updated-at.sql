-- Fix: View case fails with "record new has no field updated_at"
-- Run once in Supabase → SQL Editor

alter table public.fraud_cases
  add column if not exists updated_at timestamptz default now();

create or replace function public.set_fraud_cases_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists fraud_cases_set_updated_at on public.fraud_cases;
create trigger fraud_cases_set_updated_at
  before update on public.fraud_cases
  for each row
  execute function public.set_fraud_cases_updated_at();
