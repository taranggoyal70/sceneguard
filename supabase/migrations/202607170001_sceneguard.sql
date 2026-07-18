create extension if not exists pgcrypto;

create table public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 80),
  retention_days integer not null default 7 check (retention_days in (1, 7, 30)),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.app_sessions (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table public.spaces (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  context text not null check (context in ('personal', 'travel', 'workplace', 'hospitality', 'retail', 'other')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.baselines (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  space_id uuid not null unique references public.spaces(id) on delete cascade,
  image_data text not null check (char_length(image_data) <= 4500000),
  width integer not null check (width between 160 and 4096),
  height integer not null check (height between 120 and 4096),
  created_at timestamptz not null default now()
);

create table public.zones (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  space_id uuid not null references public.spaces(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 60),
  sensitivity numeric(5,4) not null check (sensitivity between 0.05 and 0.4),
  x numeric(7,6) not null check (x between 0 and 1),
  y numeric(7,6) not null check (y between 0 and 1),
  width numeric(7,6) not null check (width between 0.04 and 1),
  height numeric(7,6) not null check (height between 0.04 and 1),
  created_at timestamptz not null default now(),
  constraint zone_inside_frame check (x + width <= 1.001 and y + height <= 1.001)
);

create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  space_id uuid not null references public.spaces(id) on delete cascade,
  zone_id uuid references public.zones(id) on delete set null,
  zone_name text not null check (char_length(zone_name) between 1 and 60),
  summary text not null check (char_length(summary) <= 140),
  reason text not null check (char_length(reason) <= 420),
  observable_changes jsonb not null default '[]'::jsonb,
  confidence numeric(5,4) not null check (confidence between 0 and 1),
  change_ratio numeric(5,4) not null check (change_ratio between 0 and 1),
  analysis_source text not null check (analysis_source in ('local', 'gpt-5.6')),
  before_image text not null check (char_length(before_image) <= 4500000),
  after_image text not null check (char_length(after_image) <= 4500000),
  review_status text not null default 'unreviewed' check (review_status in ('unreviewed', 'expected', 'concern')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create table public.security_events (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete set null,
  event_type text not null check (char_length(event_type) between 1 and 80),
  ip_hash text not null check (char_length(ip_hash) = 64),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index spaces_user_created_idx on public.spaces(user_id, created_at desc);
create index zones_user_space_idx on public.zones(user_id, space_id);
create index incidents_user_created_idx on public.incidents(user_id, created_at desc);
create index app_sessions_user_idx on public.app_sessions(user_id);
create index security_events_user_created_idx on public.security_events(user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.app_sessions enable row level security;
alter table public.spaces enable row level security;
alter table public.baselines enable row level security;
alter table public.zones enable row level security;
alter table public.incidents enable row level security;
alter table public.security_events enable row level security;

create policy "profiles_owned" on public.profiles for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "sessions_owned" on public.app_sessions for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "spaces_owned" on public.spaces for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "baselines_owned" on public.baselines for all using (auth.uid() = user_id) with check (auth.uid() = user_id and exists (select 1 from public.spaces where spaces.id = baselines.space_id and spaces.user_id = auth.uid()));
create policy "zones_owned" on public.zones for all using (auth.uid() = user_id) with check (auth.uid() = user_id and exists (select 1 from public.spaces where spaces.id = zones.space_id and spaces.user_id = auth.uid()));
create policy "incidents_owned" on public.incidents for all using (auth.uid() = user_id) with check (auth.uid() = user_id and exists (select 1 from public.spaces where spaces.id = incidents.space_id and spaces.user_id = auth.uid()));
create policy "security_events_read_own" on public.security_events for select using (auth.uid() = user_id);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (user_id, display_name)
  values (new.id, left(coalesce(nullif(trim(new.raw_user_meta_data ->> 'display_name'), ''), split_part(new.email, '@', 1)), 80));
  return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

revoke all on all tables in schema public from anon;
grant usage on schema public to authenticated;
grant select, insert, update, delete on public.profiles, public.app_sessions, public.spaces, public.baselines, public.zones, public.incidents to authenticated;
grant select on public.security_events to authenticated;
