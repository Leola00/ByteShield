-- Password security: always store bcrypt hashes (never plain text)
-- Run in Supabase → SQL Editor

create extension if not exists "pgcrypto";

alter table public.analysts add column if not exists password text;

-- Auto-hash whenever a plain password is typed in Table Editor
create or replace function public.analysts_hash_password()
returns trigger
language plpgsql
as $$
begin
  if new.password is not null
     and length(trim(new.password)) > 0
     and new.password !~ '^\$2[abxy]?\$' then
    -- bcrypt via pgcrypto (one-way hash — cannot be decrypted)
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

-- Hide password hashes from anon/authenticated API clients (backend uses service role)
revoke select on public.analysts from anon, authenticated;
grant select (
  id, auth_user_id, full_name, email, role, team,
  avatar, phone, phone_code, bio, created_at, updated_at
) on public.analysts to anon, authenticated;

grant insert, update, delete on public.analysts to anon, authenticated;
-- password column: only service_role / table editor (postgres) can read full row

comment on column public.analysts.password is
  'bcrypt hash only ($2a$...). Type a plain password in Table Editor once — trigger hashes it.';
