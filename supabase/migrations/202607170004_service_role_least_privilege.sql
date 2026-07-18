-- The backend service role is limited to security logging, retention cleanup,
-- account-role administration, and read-only verification/export support.
grant select on public.profiles, public.app_sessions, public.spaces, public.baselines, public.zones, public.incidents, public.security_events to service_role;
grant update (role) on public.profiles to service_role;
grant delete on public.incidents, public.security_events to service_role;
