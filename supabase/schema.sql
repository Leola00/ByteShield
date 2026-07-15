-- ByteShield Fraud Operations — Supabase schema
-- Run in: Supabase Dashboard → SQL Editor → New query → Run

create extension if not exists "pgcrypto";

create table if not exists public.fraud_cases (
  id uuid primary key default gen_random_uuid(),
  case_id text not null unique,
  source text,
  content text,
  fraud_score numeric default 0,
  fraud_category text,
  ai_summary text,
  ai_recommendation text,
  iocs jsonb default '{}'::jsonb,
  status text not null default 'Pending Review',
  assigned_to text,
  internal_notes text,
  created_at timestamptz not null default now(),

  -- Fields used by the existing Fraud Ops UI (do not remove)
  content_type text default 'Message',
  preview text,
  campaign_id text,
  screenshot_data_url text,
  reasoning jsonb default '[]'::jsonb,
  urls jsonb default '[]'::jsonb,
  emails jsonb default '[]'::jsonb,
  phones jsonb default '[]'::jsonb,
  investigation jsonb,
  decision jsonb,
  updated_at timestamptz default now()
);

-- Safe to re-run if the table already exists without this column
alter table public.fraud_cases
  add column if not exists internal_notes text;

create index if not exists fraud_cases_status_idx on public.fraud_cases (status);
create index if not exists fraud_cases_created_at_idx on public.fraud_cases (created_at desc);
create index if not exists fraud_cases_category_idx on public.fraud_cases (fraud_category);

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

alter table public.fraud_cases enable row level security;

drop policy if exists "Allow anon select fraud_cases" on public.fraud_cases;
create policy "Allow anon select fraud_cases"
  on public.fraud_cases for select
  to anon, authenticated
  using (true);

drop policy if exists "Allow anon insert fraud_cases" on public.fraud_cases;
create policy "Allow anon insert fraud_cases"
  on public.fraud_cases for insert
  to anon, authenticated
  with check (true);

drop policy if exists "Allow anon update fraud_cases" on public.fraud_cases;
create policy "Allow anon update fraud_cases"
  on public.fraud_cases for update
  to anon, authenticated
  using (true)
  with check (true);
