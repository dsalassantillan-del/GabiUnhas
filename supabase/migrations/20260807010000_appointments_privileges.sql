-- Restrict appointments access to the privileges required by the frontend
-- and the Google Calendar Edge Functions. RLS and its policies are unchanged.

-- Remove implicit table privileges inherited by every database role.
revoke all privileges
on table public.appointments
from public;

-- Anonymous users must not have table-level access to appointments.
revoke all privileges
on table public.appointments
from anon;

-- Rebuild authenticated access as an explicit CRUD allowlist. This also
-- removes TRUNCATE, REFERENCES and TRIGGER if they were previously granted.
revoke all privileges
on table public.appointments
from authenticated;

grant select, insert, update, delete
on table public.appointments
to authenticated;

-- Edge Functions read appointments and persist google_calendar_event_id.
-- Rebuild service_role access without granting INSERT, DELETE, TRUNCATE,
-- REFERENCES or TRIGGER.
revoke all privileges
on table public.appointments
from service_role;

grant select, update
on table public.appointments
to service_role;
