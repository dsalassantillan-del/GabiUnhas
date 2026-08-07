create or replace function public.disconnect_google_calendar(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    delete from private.google_calendar_tokens
    where user_id = p_user_id;

    update public.google_calendar_connections
    set
        is_active = false,
        disconnected_at = now()
    where user_id = p_user_id;
end;
$$;

revoke all on function public.disconnect_google_calendar(uuid) from public;
revoke all on function public.disconnect_google_calendar(uuid) from anon;
revoke all on function public.disconnect_google_calendar(uuid) from authenticated;
grant execute on function public.disconnect_google_calendar(uuid) to service_role;
