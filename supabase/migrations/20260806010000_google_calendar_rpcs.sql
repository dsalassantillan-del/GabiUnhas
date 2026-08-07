-- SECURITY DEFINER RPCs are the only application path into the private schema.
-- Every RPC is executable exclusively by service_role.

create or replace function public.create_google_oauth_state(
    p_user_id uuid,
    p_state text,
    p_expires_at timestamptz
)
returns void
language plpgsql
security definer
set search_path = 'public', 'private'
as $$
begin
    delete from private.google_oauth_states
    where user_id = p_user_id
       or expires_at <= now();

    insert into private.google_oauth_states (
        state,
        user_id,
        expires_at
    )
    values (
        p_state,
        p_user_id,
        p_expires_at
    );
end;
$$;

create or replace function public.consume_google_oauth_state(
    p_state text
)
returns uuid
language plpgsql
security definer
set search_path = 'public', 'private'
as $$
declare
    v_user_id uuid;
begin
    delete from private.google_oauth_states
    where state = p_state
      and expires_at > now()
    returning user_id into v_user_id;

    return v_user_id;
end;
$$;

create or replace function public.save_google_calendar_tokens(
    p_user_id uuid,
    p_access_token text,
    p_refresh_token text,
    p_token_type text,
    p_scopes text,
    p_access_token_expires_at timestamptz
)
returns void
language plpgsql
security definer
set search_path = 'public', 'private'
as $$
begin
    insert into private.google_calendar_tokens (
        user_id,
        access_token,
        refresh_token,
        token_type,
        scopes,
        access_token_expires_at,
        updated_at
    )
    values (
        p_user_id,
        p_access_token,
        p_refresh_token,
        coalesce(p_token_type, 'Bearer'),
        p_scopes,
        p_access_token_expires_at,
        now()
    )
    on conflict (user_id)
    do update set
        access_token = excluded.access_token,
        refresh_token = excluded.refresh_token,
        token_type = excluded.token_type,
        scopes = excluded.scopes,
        access_token_expires_at =
            excluded.access_token_expires_at,
        updated_at = now();
end;
$$;

create or replace function public.get_google_calendar_tokens(
    p_user_id uuid
)
returns table (
    access_token text,
    refresh_token text,
    token_type text,
    scopes text,
    access_token_expires_at timestamptz
)
language sql
security definer
set search_path = 'public', 'private'
as $$
    select
        t.access_token,
        t.refresh_token,
        t.token_type,
        t.scopes,
        t.access_token_expires_at
    from private.google_calendar_tokens as t
    where t.user_id = p_user_id
    limit 1;
$$;

create or replace function public.update_google_calendar_access_token(
    p_user_id uuid,
    p_access_token text,
    p_access_token_expires_at timestamptz,
    p_token_type text default 'Bearer',
    p_scopes text default null
)
returns void
language plpgsql
security definer
set search_path = 'public', 'private'
as $$
begin
    update private.google_calendar_tokens
    set
        access_token = p_access_token,
        access_token_expires_at =
            p_access_token_expires_at,
        token_type =
            coalesce(
                p_token_type,
                token_type,
                'Bearer'
            ),
        scopes =
            coalesce(
                p_scopes,
                scopes
            ),
        updated_at = now()
    where user_id = p_user_id;

    if not found then
        raise exception
            'Google Calendar tokens not found for user';
    end if;
end;
$$;

revoke all on function public.create_google_oauth_state(uuid, text, timestamptz)
from public;
revoke all on function public.create_google_oauth_state(uuid, text, timestamptz)
from anon;
revoke all on function public.create_google_oauth_state(uuid, text, timestamptz)
from authenticated;
grant execute on function public.create_google_oauth_state(uuid, text, timestamptz)
to service_role;

revoke all on function public.consume_google_oauth_state(text)
from public;
revoke all on function public.consume_google_oauth_state(text)
from anon;
revoke all on function public.consume_google_oauth_state(text)
from authenticated;
grant execute on function public.consume_google_oauth_state(text)
to service_role;

revoke all on function public.save_google_calendar_tokens(
    uuid,
    text,
    text,
    text,
    text,
    timestamptz
)
from public;
revoke all on function public.save_google_calendar_tokens(
    uuid,
    text,
    text,
    text,
    text,
    timestamptz
)
from anon;
revoke all on function public.save_google_calendar_tokens(
    uuid,
    text,
    text,
    text,
    text,
    timestamptz
)
from authenticated;
grant execute on function public.save_google_calendar_tokens(
    uuid,
    text,
    text,
    text,
    text,
    timestamptz
)
to service_role;

revoke all on function public.get_google_calendar_tokens(uuid)
from public;
revoke all on function public.get_google_calendar_tokens(uuid)
from anon;
revoke all on function public.get_google_calendar_tokens(uuid)
from authenticated;
grant execute on function public.get_google_calendar_tokens(uuid)
to service_role;

revoke all on function public.update_google_calendar_access_token(
    uuid,
    text,
    timestamptz,
    text,
    text
)
from public;
revoke all on function public.update_google_calendar_access_token(
    uuid,
    text,
    timestamptz,
    text,
    text
)
from anon;
revoke all on function public.update_google_calendar_access_token(
    uuid,
    text,
    timestamptz,
    text,
    text
)
from authenticated;
grant execute on function public.update_google_calendar_access_token(
    uuid,
    text,
    timestamptz,
    text,
    text
)
to service_role;
