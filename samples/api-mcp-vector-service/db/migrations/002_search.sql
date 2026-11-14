-- planted: SECURITY DEFINER similarity search without search_path (bypasses RLS)
create or replace function match_chunks(query_embedding vector(1536), match_count int)
returns table (id bigint, content text, similarity float)
language sql security definer
as $$
    select c.id, c.content, 1 - (c.embedding <=> query_embedding) as similarity
    from public.document_chunks c
    order by c.embedding <=> query_embedding
    limit match_count;
$$;

-- planted: dynamic SQL by concatenation
create or replace function purge_table(tbl text) returns void
language plpgsql
as $$
begin
    execute 'delete from ' || tbl;
end;
$$;

-- correct examples (must not be flagged)
create or replace function safe_count(tbl text) returns bigint
language plpgsql security definer set search_path = public, pg_temp
as $$
declare n bigint;
begin
    execute format('select count(*) from %I', tbl) into n;
    return n;
end;
$$;

create index documents_tenant_idx on public.documents (tenant_id);
