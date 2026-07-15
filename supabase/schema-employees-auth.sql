-- ByteShield employee sign-in table
-- Run once in Supabase → SQL Editor
--
-- How you use it:
-- 1. Table Editor → analysts → Insert row
-- 2. Fill: full_name, email, password (type the plain password)
-- 3. Save — password is auto-hashed
-- 4. Employee signs in with that email + password
-- 5. To reset: edit the password cell with a new plain password and save

create extension if not exists "pgcrypto";

create table if not exists public.analysts (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique,
  full_name text not null,
  email text not null unique,
  role text not null default 'Fraud Analyst',
  team text default 'Fraud Team',
  avatar text,
  phone text,
  phone_code text default '+966',
  bio text,
  password text,
  created_at timestamptz not null default now(),
  updated_at timestamptz default now()
);

-- Add password column if table already existed without it
alter table public.analysts add column if not exists password text;

create index if not exists analysts_email_idx on public.analysts (email);

-- Auto-hash password when you type a plain password in Table Editor (bcrypt, not reversible)
create or replace function public.analysts_hash_password()
returns trigger
language plpgsql
as $$
begin
  if new.password is not null
     and length(trim(new.password)) > 0
     and new.password !~ '^\$2[abxy]?\$' then
    new.password := crypt(trim(new.password), gen_salt('bf', 12));
  end if;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists trg_analysts_hash_password on public.analysts;
create trigger trg_analysts_hash_password
  before insert or update of password on public.analysts
  for each row
  execute function public.analysts_hash_password();

alter table public.analysts enable row level security;

drop policy if exists "analysts_select" on public.analysts;
create policy "analysts_select" on public.analysts
  for select to anon, authenticated using (true);

drop policy if exists "analysts_insert" on public.analysts;
create policy "analysts_insert" on public.analysts
  for insert to anon, authenticated with check (true);

drop policy if exists "analysts_update" on public.analysts;
create policy "analysts_update" on public.analysts
  for update to anon, authenticated using (true) with check (true);

-- Do not expose password hashes over the public API
revoke select on public.analysts from anon, authenticated;
grant select (
  id, auth_user_id, full_name, email, role, team,
  avatar, phone, phone_code, bio, created_at, updated_at
) on public.analysts to anon, authenticated;
grant insert, update, delete on public.analysts to anon, authenticated;

comment on column public.analysts.password is
  'bcrypt hash only. Type plain password in Table Editor — it is hashed automatically.';

-- Example employee (password becomes a hash on insert):
-- insert into public.analysts (full_name, email, password, role, team)
-- values ('Sara Al-Qahtani', 'sara@alinma.com', 'ChangeMe123', 'Fraud Analyst', 'Fraud Team');
