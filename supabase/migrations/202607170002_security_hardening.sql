do $$
begin
  create type public.account_role as enum ('owner', 'member');
exception
  when duplicate_object then null;
end $$;

alter table public.profiles
  add column if not exists role public.account_role not null default 'owner';

alter table public.baselines drop constraint if exists baselines_image_data_check;
alter table public.baselines add constraint baselines_encrypted_image_check
  check (char_length(image_data) <= 6100000 and image_data like 'v1:%');

alter table public.incidents drop constraint if exists incidents_before_image_check;
alter table public.incidents drop constraint if exists incidents_after_image_check;
alter table public.incidents add constraint incidents_encrypted_before_image_check
  check (char_length(before_image) <= 6100000 and before_image like 'v1:%');
alter table public.incidents add constraint incidents_encrypted_after_image_check
  check (char_length(after_image) <= 6100000 and after_image like 'v1:%');

-- A signed-in user may update account preferences, but never grant themselves a role.
revoke update on public.profiles from authenticated;
grant update (display_name, retention_days, updated_at) on public.profiles to authenticated;

create or replace function public.current_account_role()
returns public.account_role
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where user_id = auth.uid();
$$;

revoke all on function public.current_account_role() from public;
grant execute on function public.current_account_role() to authenticated;
