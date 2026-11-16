-- strutvane:migration
-- name: strutvane_auth_identity
-- dialect: postgres
-- Tables of the persistent identity (@strutvane/auth on Better Auth 1.7.23) and the shared
-- rate-limit counters. Shipped by @strutvane/auth and applied by `sv migrate` (package
-- migrations). Idempotent (IF NOT EXISTS), so apps that created them with `sv auth:migration`
-- are unaffected. test/integration/app-identity.test.ts checks it matches Better Auth's schema.
create table if not exists "user" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "name" text not null, "email" text not null unique, "emailVerified" boolean not null, "image" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);
--> statement-breakpoint
create table if not exists "session" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "expiresAt" timestamptz not null, "token" text not null unique, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null, "ipAddress" text, "userAgent" text, "userId" uuid not null references "user" ("id") on delete cascade, "activeOrganizationId" text);
--> statement-breakpoint
create table if not exists "account" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "accountId" text not null, "providerId" text not null, "userId" uuid not null references "user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" timestamptz, "refreshTokenExpiresAt" timestamptz, "scope" text, "password" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null);
--> statement-breakpoint
create table if not exists "verification" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "identifier" text not null, "value" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);
--> statement-breakpoint
create table if not exists "organization" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "name" text not null, "slug" text not null unique, "logo" text, "createdAt" timestamptz not null, "metadata" text);
--> statement-breakpoint
create table if not exists "member" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "organizationId" uuid not null references "organization" ("id") on delete cascade, "userId" uuid not null references "user" ("id") on delete cascade, "role" text not null, "createdAt" timestamptz not null);
--> statement-breakpoint
create table if not exists "invitation" ("id" uuid default pg_catalog.gen_random_uuid() not null primary key, "organizationId" uuid not null references "organization" ("id") on delete cascade, "email" text not null, "role" text, "status" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "inviterId" uuid not null references "user" ("id") on delete cascade);
--> statement-breakpoint
create index if not exists "session_userId_idx" on "session" ("userId");
--> statement-breakpoint
create index if not exists "account_userId_idx" on "account" ("userId");
--> statement-breakpoint
create index if not exists "verification_identifier_idx" on "verification" ("identifier");
--> statement-breakpoint
create index if not exists "member_organizationId_idx" on "member" ("organizationId");
--> statement-breakpoint
create index if not exists "member_userId_idx" on "member" ("userId");
--> statement-breakpoint
create index if not exists "invitation_organizationId_idx" on "invitation" ("organizationId");
--> statement-breakpoint
create index if not exists "invitation_email_idx" on "invitation" ("email");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "strutvane_rate_limits" (key text PRIMARY KEY, count integer NOT NULL, reset_at timestamptz NOT NULL);
