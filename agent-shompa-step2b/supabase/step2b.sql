-- Agent Shompa · Step 2b · file vault (Cloudflare R2)
-- Run once in Supabase → SQL Editor → New query → paste → Run. Safe to run again.
-- Supabase keeps only the file's name, size and what it belongs to.
-- The file itself lives in the private R2 bucket "shompa-files".

create table if not exists public.shompa_files (
  id           uuid primary key default gen_random_uuid(),
  owner        uuid not null default auth.uid() references auth.users(id) on delete cascade,
  r2_key       text not null unique,          -- path inside the bucket, always starts with the owner's id
  file_name    text not null,                 -- original name, e.g. "Fastness report SR-1234.pdf"
  content_type text,
  size_bytes   bigint,
  category     text not null default 'other'  -- dev_swatch, lab_report, fastness, problem_photo, other
               check (category in ('dev_swatch','lab_report','fastness','problem_photo','other')),
  source_app   text not null default 'shompa' check (source_app in ('shompa','saila')),
  note         text,                          -- optional: SR, batch, buyer, what the file shows
  created_at   timestamptz not null default now(),
  deleted_at   timestamptz
);
create index if not exists shompa_files_owner_idx on public.shompa_files (owner, created_at desc);

alter table public.shompa_files enable row level security;
drop policy if exists own_rows on public.shompa_files;
create policy own_rows on public.shompa_files for all to authenticated
  using (owner = auth.uid()) with check (owner = auth.uid() and r2_key like auth.uid()::text || '/%');
