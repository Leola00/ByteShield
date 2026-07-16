-- Threaded comments on internal notes
-- Run once in Supabase → SQL Editor

alter table public.internal_notes
  add column if not exists parent_note_id uuid references public.internal_notes(id) on delete cascade;

create index if not exists internal_notes_parent_note_id_idx
  on public.internal_notes (parent_note_id);
