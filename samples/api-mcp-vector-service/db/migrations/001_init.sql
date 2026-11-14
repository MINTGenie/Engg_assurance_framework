-- fixture with planted defects
create extension if not exists vector;

create table public.documents (
    id bigint generated always as identity primary key,
    tenant_id uuid not null,
    title text not null,
    body text not null
);

-- planted: embeddings table without row level security and without an ANN index
create table public.document_chunks (
    id bigint generated always as identity primary key,
    document_id bigint references public.documents (id),
    content text not null,
    embedding vector(1536)
);

alter table public.documents enable row level security;

-- planted: policy that lets every role write every row
create policy "documents_all" on public.documents
    for all to public using (true) with check (true);

create table public.audit_log (
    id bigint generated always as identity primary key,
    actor text,
    action text, -- this comment contains a ';' on purpose
    created_at timestamptz default now()
);
alter table public.audit_log enable row level security;

-- planted: write access for the anonymous role
grant all on table public.document_chunks to anon;

-- planted: role password in a migration
create role report_reader login password 'fixture-not-real-pw';
