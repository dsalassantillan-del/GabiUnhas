-- Google Calendar persistence and OAuth state.
-- This migration is intentionally data-preserving: it creates missing objects
-- and manages policies/grants without dropping tables or existing rows.

create schema if not exists private;

revoke all on schema private from public;
revoke all on schema private from anon;
revoke all on schema private from authenticated;
grant usage on schema private to service_role;

create table if not exists public.google_calendar_connections (
    id uuid
        primary key
        default gen_random_uuid(),
    user_id uuid
        not null,
    google_email text,
    calendar_id text
        default 'primary',
    is_active boolean
        not null
        default false,
    connected_at timestamptz,
    disconnected_at timestamptz,
    created_at timestamptz
        not null
        default now(),
    updated_at timestamptz
        not null
        default now(),
    constraint google_calendar_connections_user_id_fkey
        foreign key (user_id)
        references auth.users(id)
        on delete cascade,
    constraint google_calendar_connections_user_unique
        unique (user_id)
);

create table if not exists private.google_calendar_tokens (
    user_id uuid
        primary key,
    access_token text,
    refresh_token text
        not null,
    token_type text
        default 'Bearer',
    scopes text,
    access_token_expires_at timestamptz,
    created_at timestamptz
        not null
        default now(),
    updated_at timestamptz
        not null
        default now(),
    constraint google_calendar_tokens_user_id_fkey
        foreign key (user_id)
        references auth.users(id)
        on delete cascade
);

create table if not exists private.google_oauth_states (
    state text
        primary key,
    user_id uuid
        not null,
    expires_at timestamptz
        not null,
    created_at timestamptz
        not null
        default now(),
    constraint google_oauth_states_user_id_fkey
        foreign key (user_id)
        references auth.users(id)
        on delete cascade
);

-- Appointments existed before the Calendar backend migration.
alter table public.appointments
    add column if not exists google_calendar_event_id text;

create index if not exists appointments_user_date_idx
on public.appointments (user_id, appointment_date);

create index if not exists appointments_user_schedule_idx
on public.appointments (
    user_id,
    appointment_date,
    start_time,
    end_time
);

-- Reconcile named constraints when the tables were originally created by hand.
do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'appointments_user_id_fkey'
          and conrelid = 'public.appointments'::regclass
    ) then
        alter table public.appointments
            add constraint appointments_user_id_fkey
            foreign key (user_id)
            references auth.users(id)
            on delete cascade;
    end if;

    if not exists (
        select 1
        from pg_constraint
        where conname = 'google_calendar_connections_user_id_fkey'
          and conrelid = 'public.google_calendar_connections'::regclass
    ) then
        alter table public.google_calendar_connections
            add constraint google_calendar_connections_user_id_fkey
            foreign key (user_id)
            references auth.users(id)
            on delete cascade;
    end if;

    if not exists (
        select 1
        from pg_constraint
        where conname = 'google_calendar_connections_user_unique'
          and conrelid = 'public.google_calendar_connections'::regclass
    ) then
        alter table public.google_calendar_connections
            add constraint google_calendar_connections_user_unique
            unique (user_id);
    end if;

    if not exists (
        select 1
        from pg_constraint
        where conname = 'google_calendar_tokens_user_id_fkey'
          and conrelid = 'private.google_calendar_tokens'::regclass
    ) then
        alter table private.google_calendar_tokens
            add constraint google_calendar_tokens_user_id_fkey
            foreign key (user_id)
            references auth.users(id)
            on delete cascade;
    end if;

    if not exists (
        select 1
        from pg_constraint
        where conname = 'google_oauth_states_user_id_fkey'
          and conrelid = 'private.google_oauth_states'::regclass
    ) then
        alter table private.google_oauth_states
            add constraint google_oauth_states_user_id_fkey
            foreign key (user_id)
            references auth.users(id)
            on delete cascade;
    end if;
end;
$$;

alter table public.google_calendar_connections
    enable row level security;

drop policy if exists
    "Users can read own calendar connection"
    on public.google_calendar_connections;

create policy
    "Users can read own calendar connection"
on public.google_calendar_connections
for select
to authenticated
using (
    auth.uid() is not null
    and auth.uid() = user_id
);

drop policy if exists
    "Users can insert own calendar connection"
    on public.google_calendar_connections;

create policy
    "Users can insert own calendar connection"
on public.google_calendar_connections
for insert
to authenticated
with check (
    auth.uid() is not null
    and auth.uid() = user_id
);

drop policy if exists
    "Users can update own calendar connection"
    on public.google_calendar_connections;

create policy
    "Users can update own calendar connection"
on public.google_calendar_connections
for update
to authenticated
using (
    auth.uid() is not null
    and auth.uid() = user_id
)
with check (
    auth.uid() is not null
    and auth.uid() = user_id
);

drop policy if exists
    "Users can delete own calendar connection"
    on public.google_calendar_connections;

create policy
    "Users can delete own calendar connection"
on public.google_calendar_connections
for delete
to authenticated
using (
    auth.uid() is not null
    and auth.uid() = user_id
);

-- Keep anonymous users out and expose only the CRUD operations required by
-- authenticated users. Edge Functions use service_role for backend writes.
revoke all on table public.google_calendar_connections from public;
revoke all on table public.google_calendar_connections from anon;
revoke all on table public.google_calendar_connections from authenticated;

grant select, insert, update, delete
on table public.google_calendar_connections
to authenticated;

grant all
on table public.google_calendar_connections
to service_role;

-- Private OAuth data must never be reachable by frontend roles.
revoke all on table private.google_calendar_tokens from public;
revoke all on table private.google_calendar_tokens from anon;
revoke all on table private.google_calendar_tokens from authenticated;

revoke all on table private.google_oauth_states from public;
revoke all on table private.google_oauth_states from anon;
revoke all on table private.google_oauth_states from authenticated;

grant select, insert, update, delete
on table private.google_calendar_tokens
to service_role;

grant select, insert, delete
on table private.google_oauth_states
to service_role;
