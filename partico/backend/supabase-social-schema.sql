-- Partico social schema upgrade (friends + parties)
-- Paste this into Supabase Dashboard > SQL Editor > Run
-- Safe to run more than once.

-- Profile fields on users
alter table partico_users add column if not exists "firstName" text;
alter table partico_users add column if not exists "lastName" text;
alter table partico_users add column if not exists phone text;
alter table partico_users add column if not exists bio text;

-- Friendships: one row per pair. status = 'pending' or 'accepted'
create table if not exists partico_friendships (
  id uuid primary key default gen_random_uuid(),
  requester_id text not null,
  addressee_id text not null,
  status text not null default 'pending',
  created_at timestamptz default now(),
  unique (requester_id, addressee_id)
);

-- Parties: the whole party object lives in data (invites are stored separately)
create table if not exists partico_parties (
  id text primary key,
  host_id text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Party invites / RSVPs: one row per guest per party
create table if not exists partico_party_invites (
  id uuid primary key default gen_random_uuid(),
  party_id text not null,
  user_id text not null,
  status text not null default 'pending',
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz default now(),
  unique (party_id, user_id)
);

create index if not exists idx_party_invites_user on partico_party_invites (user_id);
create index if not exists idx_party_invites_party on partico_party_invites (party_id);
create index if not exists idx_parties_host on partico_parties (host_id);

-- Backend uses the service role key (bypasses RLS); block the public anon key
alter table partico_friendships enable row level security;
alter table partico_parties enable row level security;
alter table partico_party_invites enable row level security;
