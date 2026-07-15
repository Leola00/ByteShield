-- ByteShield Fraud Ops — analysts, internal_notes, fraud_cases extras
-- Run in Supabase SQL Editor

create extension if not exists "pgcrypto";

-- ── analysts ──────────────────────────────────────────────
create table if not exists public.analysts (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique references auth.users(id) on delete set null,
  full_name text not null,
  email text not null unique,
  role text not null default 'Fraud Analyst',
  team text default 'Fraud Team',
  avatar text,
  phone text,
  phone_code text default '+966',
  bio text,
  created_at timestamptz not null default now(),
  updated_at timestamptz default now()
);

create index if not exists analysts_email_idx on public.analysts (email);
create index if not exists analysts_auth_user_id_idx on public.analysts (auth_user_id);

-- ── internal_notes ──────────────────────────────────────
create table if not exists public.internal_notes (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.fraud_cases(id) on delete cascade,
  analyst_id uuid references public.analysts(id) on delete set null,
  note text not null,
  created_at timestamptz not null default now()
);

create index if not exists internal_notes_case_id_idx on public.internal_notes (case_id);
create index if not exists internal_notes_analyst_id_idx on public.internal_notes (analyst_id);
create index if not exists internal_notes_created_at_idx on public.internal_notes (created_at desc);

-- ── fraud_cases extras for actions / review ─────────────
alter table public.fraud_cases add column if not exists reviewed_by text;
alter table public.fraud_cases add column if not exists reviewed_at timestamptz;
alter table public.fraud_cases add column if not exists decision text;
alter table public.fraud_cases add column if not exists decision_payload jsonb;

-- ── RLS ─────────────────────────────────────────────────
alter table public.analysts enable row level security;
alter table public.internal_notes enable row level security;

drop policy if exists "analysts_select" on public.analysts;
create policy "analysts_select" on public.analysts for select to anon, authenticated using (true);

drop policy if exists "analysts_update_own" on public.analysts;
create policy "analysts_update_own" on public.analysts for update to authenticated
  using (auth.uid() = auth_user_id)
  with check (auth.uid() = auth_user_id);

drop policy if exists "analysts_insert" on public.analysts;
create policy "analysts_insert" on public.analysts for insert to anon, authenticated with check (true);

drop policy if exists "notes_select" on public.internal_notes;
create policy "notes_select" on public.internal_notes for select to anon, authenticated using (true);

drop policy if exists "notes_insert" on public.internal_notes;
create policy "notes_insert" on public.internal_notes for insert to anon, authenticated with check (true);

drop policy if exists "notes_delete" on public.internal_notes;
create policy "notes_delete" on public.internal_notes for delete to anon, authenticated using (true);

drop policy if exists "notes_update" on public.internal_notes;
create policy "notes_update" on public.internal_notes for update to anon, authenticated using (true) with check (true);

-- Realtime (ignore error if already added)
do $$
begin
  alter publication supabase_realtime add table public.fraud_cases;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.internal_notes;
exception when duplicate_object then null;
end $$;

-- Employees live in public.analysts.
-- Add them with password via: backend/scripts/add-employee.js or POST /api/analysts
-- (see SETUP-FRAUD-OPS.md). Do not insert rows alone — Auth password is required for login.
