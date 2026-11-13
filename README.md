# Multi-Tenant User Management

Go API using Gin and PostgreSQL through pgxpool. The existing Compose service
and applied migration are managed separately; API startup does not alter schema.

## Submission documentation and prerequisites

- Go 1.26; Docker Engine and Docker Compose v2; curl. PostgreSQL 16 runs in Compose,
  while the API runs on the host. Swagger UI is embedded; no API image or separate frontend is included.
- [Interactive Swagger UI](http://localhost:8080/swagger/index.html): all 30 application operations / 19 paths
- [Generated Swagger JSON](docs/swagger/swagger.json) and [YAML](docs/swagger/swagger.yaml)
- [Nine-table Mermaid ER diagram](docs/erd.md)
- [Architecture and security tradeoffs](docs/design.md)
- [Requirements checklist with evidence](docs/requirements-checklist.md)
- [Actual Phase 5 validation results](docs/validation.md)

For a new local environment, preserve existing configuration and create a private
copy only if `.env` does not exist:

```sh
test -f .env || (umask 077; cp .env.example .env)
docker compose up -d postgres
docker compose ps
docker compose exec -T postgres pg_isready -U app -d multitenant
```

Configure `DATABASE_URL` privately to match the initialized database, URL-encoding
special characters. Compose currently contains a fixed development-only database
credential; changing `.env` alone does not change that setting or an initialized
password. Do not use this credential or the public seed account in production.
The example binds the API to loopback; the runtime fallback without `HTTP_ADDR`
is still `:8080` (all interfaces).

Generate a JWT secret without printing it or replacing an existing real key:

```sh
python3 - <<'PYCONFIG'
from pathlib import Path
import os, secrets
p = Path('.env'); s = p.read_text()
marker = 'JWT_SECRET=REPLACE_WITH_A_RANDOM_SECRET'
if marker in s:
    p.write_text(s.replace(marker, 'JWT_SECRET=' + secrets.token_hex(32)))
os.chmod(p, 0o600)
PYCONFIG
```

Migrations 001 and 002 are already applied in this workspace. Do not rerun them.
Phase 6 requires migration 003, which must be approved and applied separately
before running the new API; see the Phase 6 instructions below. For a
fresh, explicitly authorized database only, apply 001 once before 002:

```sh
# Fresh database ONLY: 001 has no internal transaction.
docker compose exec -T \
  -e PGOPTIONS='-c search_path=public -c lock_timeout=5s -c statement_timeout=60s' \
  postgres psql -X -U app -d multitenant -v ON_ERROR_STOP=1 \
  --single-transaction -f - < migrations/001_init.sql

# Only if 001 exists and 002 is not applied. 002 already contains BEGIN/COMMIT.
docker compose exec -T \
  -e PGOPTIONS='-c search_path=public -c lock_timeout=5s -c statement_timeout=60s' \
  postgres psql -X -U app -d multitenant -v ON_ERROR_STOP=1 \
  -f - < migrations/002_membership_lifecycle.sql
```

Verify applied state with read-only SQL before migration commands:

```sql
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema='public' AND table_name='tenant_users'
ORDER BY ordinal_position;
SELECT conname, convalidated, pg_get_constraintdef(oid)
FROM pg_constraint WHERE conrelid='public.tenant_users'::regclass;
```

API startup never runs migrations, seed or bootstrap. There is no migration-history
runner; these SQL files are not idempotent. The development seed/bootstrap commands
below mutate data and require explicit operator approval. The existing development
administrator was already bootstrapped during the approved live smoke test; do not
repeat the initial-only bootstrap in this workspace.

## Run locally

Copy `.env.example` to `.env` and replace `REPLACE_ME` with the password configured
in your existing PostgreSQL service. URL-encode special characters in credentials.
Set `JWT_SECRET` to a randomly generated secret of at least 32 bytes (for example,
`openssl rand -hex 32`). Never commit the generated secret. The template value is
intentionally rejected at startup. Preserve existing keys.
Start the application from the project root:

```sh
go run ./cmd/api
```

The application automatically loads an optional `.env` file from its current
working directory using godotenv. Existing environment variables take precedence,
including variables set to an empty value. You can also run entirely from process
environment variables without a `.env` file. An unreadable or malformed file causes
startup to fail. `.env` is ignored by Git; `.env.example` remains the template.

`HTTP_ADDR` defaults to `:8080`, `DB_MAX_CONNS` to `10`, `DB_TIMEOUT` to `5s`,
and `SHUTDOWN_TIMEOUT` to `10s`. `DATABASE_URL` is required. Startup checks the
database connection and fails if it is unavailable. SIGINT and SIGTERM stop
accepting requests and allow in-flight requests to finish before closing the pool.

## Operational endpoints

- `GET /health`: application liveness, returns `200 {"status":"ok"}` independently of database health.
- `GET /ready`: performs a bounded database ping; returns `200 {"status":"ready"}` or `503`.

Errors use `{"error":{"code":"database_unavailable","message":"Database is unavailable"}}`.
Unknown routes, unsupported methods, and recovered handler panics use the same
envelope. Logs are JSON and exclude query strings, request bodies, and credentials.
Tenant, user and membership management routes require JWT authentication and
evaluate current tenant-scoped RBAC grants on every request (see Phase 4).

## Authentication

The application uses handler → service → repository layers in `internal/auth`.
`JWT_ISSUER` defaults to `multitenant-user-management`, `ACCESS_TOKEN_TTL` to `15m`,
and `REFRESH_TOKEN_TTL` to `168h`. Access TTL must be between 1 second and 1 hour;
refresh TTL must exceed it. There is no default JWT secret.

| Endpoint | JSON body | Success |
| --- | --- | --- |
| `POST /api/v1/auth/login` | `email`, `password`, `tenant_code` | 200 token pair |
| `POST /api/v1/auth/refresh` | `refresh_token` | 200 new token pair; old refresh token is revoked |
| `POST /api/v1/auth/logout` | `refresh_token` | 204; refresh token revoked |

Requests require `Content-Type: application/json`; unknown fields, extra JSON
values, missing fields, and bodies over 16 KiB are rejected. Login accepts passwords
up to bcrypt's 72-byte limit. Email whitespace is trimmed and PostgreSQL `LOWER`
is applied to both the stored email and input, matching the unique email index.
Tenant codes are trimmed and case-sensitive. Users must not be soft-deleted;
the schema has no user status column. Tenants and memberships must be active.
Login failures return the same 401 response for unknown users, bad passwords,
wrong tenants, deleted users, and suspended tenants/memberships. Failure audits
do not store submitted passwords, email addresses, or tokens.

A successful login/refresh returns:

```json
{"access_token":"<JWT>","refresh_token":"<opaque-token>","token_type":"Bearer","expires_in":900}
```

Access JWTs use HS256 and contain `sub` (user ID), `tenant_id`, `iss`, `iat`, `exp`,
and `jti`. Validation pins the algorithm and issuer and requires valid IDs and
required claims. Refresh tokens contain 256 bits of cryptographic randomness;
only their SHA-256 hashes are stored. Rotation uses row locks and a transaction,
so concurrent reuse has one winner. Expired, revoked, or invalid-account refresh
tokens are rejected. Store each new refresh token before the next refresh. A
lost refresh response cannot be retried with the consumed old token; log in again.
Logout does not revoke already issued access JWTs; they remain valid until expiry.
Suspension/deletion blocks new logins and refreshes; existing access JWTs also
remain valid until expiry. There is no refresh-token family replay revocation.

`auth.Authenticate(tokens)` protects the Phase 3 management routes. It validates
only the Authorization bearer JWT and installs a typed identity in the request
context, retrieved with `auth.IdentityFromContext`. Protected handlers/services
must use that tenant ID to scope repository queries. Headers, queries, or body
fields naming a tenant never establish trusted identity. Authorization checks must
return 403 for authenticated-but-forbidden actions and 404 for cross-tenant
resource lookups. Role administration endpoints are documented under Phase 4.

Errors retain the shared `{"error":{"code":"unauthorized","message":"Invalid or missing authentication"}}`
envelope: malformed requests return 400, invalid credentials return 401, forbidden
actions return 403, and internal failures return a sanitized 500. Authentication
responses set `Cache-Control: no-store`. Login audit writes are best effort and
bounded; a failed audit emits a fixed warning without request or driver details.

### Development provisioning and curl examples

There is no public registration endpoint and no automatically provisioned account.
For a development database only, explicitly run:

```sh
sh scripts/seed-dev.sh --development
```

This idempotent script creates tenant `dev-auth`, user `dev-auth@example.test`,
and their membership. Its documented development-only password is
`DevOnly-ChangeMe-2026!`. Never run this seed against production. It does not
overwrite existing credentials, reactivate suspended records, create roles, or
grant permissions; conflicting records cause the transaction to roll back.

```sh
# Approved local-development example only; do not run during read-only validation.
(
set +x
set -eu
umask 077
api_example_dir=$(mktemp -d)
trap 'rm -rf -- "$api_example_dir"' EXIT

# Prepare the public development fixture request without printing its password.
python3 - "$api_example_dir" <<'PYCREDENTIAL'
from pathlib import Path
import json, re, sys
p = Path(sys.argv[1])
s = Path('cmd/seed-dev/main.go').read_text()
password = re.search(r'^const devPassword = "([^"\n]+)"', s, re.M).group(1)
(p/'login.json').write_text(json.dumps({
    'email':'dev-auth@example.test', 'password':password, 'tenant_code':'dev-auth'
}))
PYCREDENTIAL

curl -sS --fail http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' --data-binary @"$api_example_dir/login.json" \
  -o "$api_example_dir/tokens.json" -w 'login HTTP %{http_code}\n'

prepare_auth_files() {
  python3 - "$api_example_dir" <<'PYTOKEN'
from pathlib import Path
import json, sys
p = Path(sys.argv[1]); t = json.loads((p/'tokens.json').read_text())
(p/'bearer.headers').write_text('Authorization: Bearer '+t['access_token']+'\n')
(p/'refresh.json').write_text(json.dumps({'refresh_token':t['refresh_token']}))
PYTOKEN
}
prepare_auth_files
curl -sS http://localhost:8080/api/v1/tenant -H @"$api_example_dir/bearer.headers"
curl -sS 'http://localhost:8080/api/v1/users?page=1&page_size=20' \
  -H @"$api_example_dir/bearer.headers"

curl -sS --fail http://localhost:8080/api/v1/auth/refresh \
  -H 'Content-Type: application/json' --data-binary @"$api_example_dir/refresh.json" \
  -o "$api_example_dir/tokens.json" -w 'refresh HTTP %{http_code}\n'
prepare_auth_files  # Both request files now use the replacement credentials.
curl -sS --fail http://localhost:8080/api/v1/auth/logout \
  -H 'Content-Type: application/json' --data-binary @"$api_example_dir/refresh.json" \
  -o /dev/null -w 'logout HTTP %{http_code}\n'
)
```

Use HTTPS outside local development. Apply deployment-level login throttling
before exposing these endpoints publicly; this module does not implement a
distributed rate limiter.

## Phase 3: tenant, user and membership management

The management code follows handler → service → repository architecture in
`internal/tenant` and `internal/user`. Shared access checks and transaction helpers
live in `internal/access`; strict JSON/error/pagination helpers live in
`internal/httpapi`.

**Authorization is fail closed.** Every management route requires a valid access
JWT and a specific permission. Phase 4 now wires a PostgreSQL-backed policy at
both the HTTP and service layers, then rechecks the same permission inside the
repository transaction after acquiring the tenant lock. Missing/invalid JWTs
return 401; active members without the required grant return 403. Tenant IDs,
role names, JWT role claims and headers do not grant authority. See Phase 4 for
the permission matrix and explicit administrator bootstrap.

### Additive migration and tenant provisioning

`001_init.sql` is unchanged. `002_membership_lifecycle.sql` adds membership
`updated_at` and `removed_at`, plus a constraint keeping removed memberships
suspended. These fields support optimistic concurrency and logical removal
without deleting refresh-token or role history. The existing authentication
queries already exclude suspended memberships. API startup never applies
migrations. Check whether migration 002 is already applied before running it again.

Apply 002 **once**, if it is not already applied, before using Phase 4. With
`DATABASE_URL` set in your shell to the intended database:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_membership_lifecycle.sql
```

Tenant creation has no HTTP endpoint. An operator with database access must
explicitly opt in to the administrative CLI:

```sh
go run ./cmd/provision-tenant --administrative --name 'Example Company' --code example-company
```

Codes are immutable, unique, lowercase ASCII letters/digits/underscores/hyphens,
start with a letter or digit, and contain at most 50 characters. Names contain
1–200 Unicode characters after trimming. Duplicate codes return a sanitized CLI
failure; there is no partial tenant or audit creation. Without the explicit Phase 4 bootstrap flags, provisioning creates only
the tenant and audit event; it grants no memberships or privileges.

### Registered management endpoints

All paths derive tenant identity exclusively from the validated JWT. There is
no tenant ID path selector or tenant ID request field.

| Method | Path | Action | Request fields |
| --- | --- | --- | --- |
| GET | `/api/v1/tenant` | `tenant:read` | None |
| PATCH | `/api/v1/tenant` | `tenant:update` | `name`, `expected_updated_at` |
| PATCH | `/api/v1/tenant/status` | `tenant:status` | `status`, `expected_updated_at` |
| POST | `/api/v1/users` | `user:create` | `email`, `full_name`, `password` |
| GET | `/api/v1/users` | `user:read` | Query filters below |
| GET | `/api/v1/users/:user_id` | `user:read` | None |
| PATCH | `/api/v1/users/:user_id` | `user:update` | Optional `email`, `full_name`, `password`; required `expected_updated_at` |
| DELETE | `/api/v1/users/:user_id` | `user:delete` | `expected_updated_at` |
| POST | `/api/v1/memberships` | `membership:create` | `user_id` |
| PATCH | `/api/v1/memberships/:user_id` | `membership:update` | `status`, `expected_updated_at` |
| DELETE | `/api/v1/memberships/:user_id` | `membership:delete` | `expected_updated_at` |

The statuses are `active` and `suspended`. With the required RBAC permission,
GET/PATCH operations return 200, creation returns 201, and deletion/removal returns
204. Authorized cross-tenant user lookups and mutations return 404. Authorization
runs first, so users without a grant receive 403 regardless of resource existence.
Malformed UUIDs, JSON or fields return 400 after authorization; duplicate emails,
duplicate memberships, shared-profile edits and stale versions return 409.
Unknown body fields (including `tenant_id`) are rejected. `X-Tenant-ID` headers
never select scope. List queries accept only documented query keys.

User lists return `{ "items": [], "page": 1, "page_size": 20, "total": 0 }`.
Supported query keys are `page` (1–1000000), `page_size` (1–100, default 20), `q`
(case-insensitive literal substring of email/name, max 200 characters), and
`membership_status` (`active` or `suspended`). Ordering is stable by creation time
then ID. Removed memberships and soft-deleted users are always excluded. Suspended
target memberships can be listed/managed by an authorized active actor.

New and changed passwords must contain 12–72 bytes and are bcrypt-hashed before
reaching the repository. They are never returned. Emails are trimmed and stored
using PostgreSQL `LOWER`, consistent with the existing global unique index.
Creating a duplicate email never overwrites credentials or silently attaches the
existing identity; attaching a known identity is an explicit membership operation.
Soft-deleted emails remain reserved by the original unique index.

**Shared identities:** users are global records. Tenant APIs return 409 for global
profile/password edits or soft-deletion while another non-removed membership
exists, even if suspended. Use tenant-local membership status/removal for shared
users. Adding membership takes a known user UUID and never exposes a global user
search. The FK establishes scope before the target profile is read; absent/deleted
targets return 404 and the membership insertion rolls back.

`expected_updated_at` must exactly match the timestamp from the latest GET response.
Copy it verbatim, preserving all fractional digits (PostgreSQL microsecond precision);
do not round to milliseconds or use the current time or Swagger sample value.
For example, `2026-01-02T03:04:05.123456Z` illustrates the format only.
After 409, GET again and review the latest state before retrying.
For user edits/deletion, use the **top-level** `updated_at` from
`GET /api/v1/users/{user_id}`, not `membership.updated_at`; for membership changes, use
`membership.updated_at` from the user response, or `updated_at` from the membership
response. Tenant edits use the tenant's `updated_at`. Updates strictly advance
versions; stale requests return 409 instead of overwriting concurrent changes.
Management writes serialize per tenant, and global user row locks coordinate
membership attachment with profile mutations. Database deadlocks/serialization
failures also map to 409; reread the resource before retrying.

Membership removal is logical: it records `removed_at`, suspends the membership,
and revokes that tenant/user's refresh tokens. It does not delete the user, role
assignments, membership row, or refresh history. Re-adding a removed membership
never revives old tokens; it returns 409 if historical role assignments exist,
until an explicit grant-review flow is implemented. Suspending a tenant revokes
its refresh tokens; suspending a membership and changing a password also revoke
relevant refresh tokens. Current database state is rechecked in each management
transaction, so an old access JWT cannot manage a suspended tenant, inactive or
removed membership, or deleted actor. All protected HTTP operations reject suspended tenants, including attempts to
reactivate them through `tenant.status`. Recovery requires an explicitly approved
operator database procedure; there is no HTTP suspension bypass.
Existing access JWTs still validate cryptographically until expiry, as described
above, but Phase 3 access checks reject their inactive database identity.

All successful tenant, user and membership mutations write transactional audit
records. Audit failures roll back the entire operation. Audits contain action,
actor, tenant and target IDs, without profile fields, passwords or tokens. No new
HTTP route is capable of provisioning a tenant or granting permissions.

### Curl examples

These requests return **403** for members without matching permissions and work
for explicitly authorized tenant administrators. Set
`ACCESS_TOKEN` privately in your shell and avoid shell tracing. These commands do
not print access or refresh tokens. Replace UUID/timestamp placeholders with
server-returned values.

```sh
curl -sS http://localhost:8080/api/v1/tenant \
  -H @/path/to/private/bearer.headers

curl -sS 'http://localhost:8080/api/v1/users?page=1&page_size=20&q=example&membership_status=active' \
  -H @/path/to/private/bearer.headers

curl -sS -X PATCH http://localhost:8080/api/v1/tenant \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"name":"New Company Name","expected_updated_at":"<tenant-updated_at>"}'

curl -sS -X PATCH http://localhost:8080/api/v1/tenant/status \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"status":"suspended","expected_updated_at":"<tenant-updated_at>"}'

# Store email/full_name/password in a private JSON file; do not echo its contents.
curl -sS http://localhost:8080/api/v1/users \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  --data-binary @/tmp/create-user.json

curl -sS 'http://localhost:8080/api/v1/users/<user-uuid>' \
  -H @/path/to/private/bearer.headers

curl -sS -X PATCH 'http://localhost:8080/api/v1/users/<user-uuid>' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"full_name":"Updated Name","expected_updated_at":"<user-updated_at>"}'

curl -sS http://localhost:8080/api/v1/memberships \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"user_id":"<existing-user-uuid>"}'

curl -sS -X PATCH 'http://localhost:8080/api/v1/memberships/<user-uuid>' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"status":"suspended","expected_updated_at":"<membership-updated_at>"}'

curl -sS -X DELETE 'http://localhost:8080/api/v1/memberships/<user-uuid>' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"expected_updated_at":"<membership-updated_at>"}'

curl -sS -X DELETE 'http://localhost:8080/api/v1/users/<user-uuid>' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"expected_updated_at":"<user-updated_at>"}'
```

### Phase 3 PostgreSQL integration tests

```sh
PHASE3_TEST_DATABASE_URL='<local-development-postgres-url>' go test ./internal/user -run TestPostgresPhase3 -v
```

Tests create an isolated schema, exclude `public` from its search path, verify the
current schema, apply all migrations there, and remove only that test schema on
cleanup. They never execute the provisioning CLI against application data.
Tenant/user/membership repositories, real HTTP handlers with a test-only granting
policy, transaction rollback, concurrent stale updates and tenant isolation are
exercised. Without the opt-in URL these tests are skipped. Phase 4 separately tests real RBAC policy and authorized HTTP flows.
Race-detector and load checks are not part of these integration commands.

## Phase 4: tenant-scoped RBAC

`internal/rbac` implements handlers, services, repositories, a database policy and
an operator-only initial bootstrap. No schema changes are required beyond the
existing migrations 001 and 002. No grants are added during API startup. Existing
members, including the development seed user, have no management rights until an
operator explicitly bootstraps or an authorized administrator assigns roles.

Permissions are exact `resource:action` pairs. Access JWTs establish only user and
tenant identity. Every protected policy check reads current identity validity and
authorization revision from PostgreSQL; permission unions may come from the
revision-keyed Phase 6 cache. Effective permissions are the distinct union of all roles
assigned to that user in that tenant. There are no wildcard permissions, implicit
administrator role-name checks or administrator headers.

### Permission matrix

| Resource | Actions | Used for |
| --- | --- | --- |
| `tenant` | `read`, `update`, `status` | Current tenant detail, profile and status |
| `user` | `create`, `read`, `update`, `delete` | Tenant-scoped user CRUD; `read` covers list and detail |
| `membership` | `create`, `update`, `delete` | Membership attachment, status and logical removal |
| `role` | `create`, `read`, `update`, `delete` | Role CRUD; `read` also lists role permissions |
| `role_permission` | `assign`, `remove` | Grant/revoke a permission on a tenant role |
| `user_role` | `assign`, `remove` | Assign/revoke roles on tenant members |
| `permission` | `read` | Read the persisted global permission catalog |
| `user_permission` | `read` | Read a tenant member's assigned roles and effective permissions |

The supported catalog contains 20 permission pairs. API grants accept only these
pairs; custom/wildcard permissions return 400. Historical unsupported identifiers
can remain in the catalog but never authorize an action or appear as effective
permissions. Catalog rows are shared immutable
identifiers, while all role/grant/assignment rows are tenant-scoped. Removing a
role permission never deletes its global catalog entry. The initial administrator
role receives the current catalog explicitly, not a wildcard.

Every protected request revalidates the tenant as active, the membership as active
and not removed, and the user as not deleted. Suspension, logical membership
removal, soft deletion, role deletion, role revocation and permission revocation
therefore affect previously issued JWTs on subsequent requests. Suspended tenants
cannot use the status API to reactivate themselves. The `/me/permissions` route
requires an active identity but no management grant; ordinary active members can
see their own empty permission set.

The HTTP middleware and services check each action. Services bind the action to
the repository context; PostgreSQL repositories recheck it inside their scoped
transaction after acquiring the tenant lock. Grant mutations use that same tenant
lock, so a request cannot pass an earlier check and then commit a write after a
permission revocation wins the lock. Reads hold a shared tenant lock until their
transaction finishes. Existing primary/unique indexes on `tenant_users`,
`user_roles`, `roles`, `role_permissions` and `permissions` support these joins.
Revision-keyed permission caches observe committed grant changes without token
renewal. Transaction-level checks continue reading grants directly.

Delegation also checks the actor's current grants inside the transaction:
assigning a permission requires both `role_permission:assign` and that permission;
assigning a role requires `user_role:assign` and every permission already on that
role. Password changes additionally require the caller to hold the target's
assigned permissions, preventing a delegated user manager from taking over a more
privileged identity. Membership activation applies the same rule to dormant role
assignments, so a membership manager cannot activate privileges they do not hold.
These checks occur after the scoped target lookup and inside the mutation
transaction. A caller cannot grant themselves new rights simply by having assignment
privileges. All role/grant mutations and related audits commit atomically. Audit
metadata records related UUIDs, without passwords, tokens or profile data.

### RBAC endpoints

Every endpoint below requires an access JWT and current active database identity.
IDs in the URL identify target resources within the JWT's tenant; they do not
select a tenant. Cross-tenant roles, target users, and assignments return 404 after
authorization. Missing/invalid JWTs return 401; insufficient grants or inactive
identities return 403. Invalid input returns 400 and duplicate grants, role names
or stale role versions return 409. Unknown JSON fields are rejected.

| Method | Path | Required permission | Body / result |
| --- | --- | --- | --- |
| POST | `/api/v1/roles` | `role:create` | `name`, optional `description`; 201 role |
| GET | `/api/v1/roles` | `role:read` | `page`, `page_size` query; 200 role page |
| GET | `/api/v1/roles/:role_id` | `role:read` | 200 role |
| PATCH | `/api/v1/roles/:role_id` | `role:update` | `name`, `description`, `expected_version`; 200 role |
| DELETE | `/api/v1/roles/:role_id` | `role:delete` | `expected_version`; 204 |
| GET | `/api/v1/permissions` | `permission:read` | 200 persisted catalog |
| GET | `/api/v1/roles/:role_id/permissions` | `role:read` | 200 role permission array |
| POST | `/api/v1/roles/:role_id/permissions` | `role_permission:assign` | `resource`, `action`; 204 |
| DELETE | `/api/v1/roles/:role_id/permissions` | `role_permission:remove` | `resource`, `action`; 204 |
| GET | `/api/v1/users/:user_id/roles` | `user_permission:read` | 200 assigned role array |
| PUT | `/api/v1/users/:user_id/roles/:role_id` | `user_role:assign` | No body; 204 |
| DELETE | `/api/v1/users/:user_id/roles/:role_id` | `user_role:remove` | No body; 204 |
| GET | `/api/v1/users/:user_id/permissions` | `user_permission:read` | 200 distinct effective permission array |
| GET | `/api/v1/me/permissions` | Active identity only | 200 caller's effective permission array |

Role list pagination has the same 1–100 page-size limit as users. Role names are
trimmed, case-sensitive, unique per tenant, and contain at most 100 characters;
descriptions are limited to 2000 characters. Role profile responses include an
opaque `version` digest of ID/name/description. Send that as `expected_version`
when changing or deleting a role. PATCH replaces the name/description profile;
omitted description becomes empty. Versions describe profile content, not grant
history. Role deletion transactionally removes only that tenant role's permission
links and user assignments, auditing each removal; unrelated roles and global
permission identifiers remain untouched.

Assigned-role listing can include suspended members' dormant assignments. Effective
permissions for a suspended target membership are empty. Removed memberships and
deleted users are not targetable through these APIs (404). The Phase 3 reattachment
safeguard remains: a removed membership with historical grants returns 409 rather
than silently restoring those grants. An approved operator process is needed to
review such historical assignments; these APIs do not expose removed members.

### Explicit initial administrator bootstrap

Do not run bootstrap against any live database without operator approval. The
application and development seed never call it automatically. This workspace's
application database was subsequently bootstrapped only during an explicitly approved live smoke test. Initial bootstrap must not be repeated.

The existing provisioning command now supports two explicit approvals plus a
selected existing user UUID. For an existing tenant, the user must already have
an active, non-removed membership and must not be deleted:

```sh
go run ./cmd/provision-tenant \
  --administrative --bootstrap-admin --existing \
  --code dev-auth --admin-user-id '<verified-active-member-uuid>'
```

For a new tenant, omit `--existing` and provide a name. The transaction creates
the tenant, attaches the selected existing non-deleted identity, creates the
`tenant-admin` role, grants the 20 catalog permissions, assigns that role and
writes operator-source audits. Any failure rolls back the complete operation:

```sh
go run ./cmd/provision-tenant \
  --administrative --bootstrap-admin \
  --name 'Example Company' --code example-company \
  --admin-user-id '<verified-existing-user-uuid>'
```

The command never creates an account, accepts a password, resets credentials,
reactivates suspended records, or changes another tenant's grants. Verify the
selected identity before approval. Without `--bootstrap-admin`, the original
`--administrative --name ... --code ...` workflow still creates only a tenant.

Bootstrap is **initial-only**, not a repair/recovery command. It refuses tenants
that already have roles, assignments or an earlier `tenant.admin_bootstrap` audit,
even if an administrator later deliberately removed their grants. Repeating it
returns a sanitized failure instead of silently restoring privileges. There is
no automatic last-administrator protection: authorized operators/admins can
remove the final administration path. Recovery then requires a separately
reviewed operator procedure. The bootstrap role name is a label, not an access
bypass; renaming it does not change its grants.

### Curl examples

Prepare a private bearer header file containing an authorized administrator's JWT; keep shell tracing disabled. These requests do not return access or refresh tokens. Replace
UUID/version placeholders with server-returned values:

```sh
curl -sS http://localhost:8080/api/v1/roles \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"name":"reader","description":"Can read tenant users"}'

curl -sS 'http://localhost:8080/api/v1/roles?page=1&page_size=20' \
  -H @/path/to/private/bearer.headers

curl -sS 'http://localhost:8080/api/v1/roles/<role-uuid>/permissions' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"resource":"user","action":"read"}'

curl -sS -X PUT 'http://localhost:8080/api/v1/users/<user-uuid>/roles/<role-uuid>' \
  -H @/path/to/private/bearer.headers

curl -sS 'http://localhost:8080/api/v1/users/<user-uuid>/permissions' \
  -H @/path/to/private/bearer.headers

curl -sS http://localhost:8080/api/v1/me/permissions \
  -H @/path/to/private/bearer.headers

curl -sS -X DELETE 'http://localhost:8080/api/v1/users/<user-uuid>/roles/<role-uuid>' \
  -H @/path/to/private/bearer.headers

curl -sS -X DELETE 'http://localhost:8080/api/v1/roles/<role-uuid>/permissions' \
  -H @/path/to/private/bearer.headers -H 'Content-Type: application/json' \
  -d '{"resource":"user","action":"read"}'
```

### RBAC tests

```sh
RBAC_TEST_DATABASE_URL='<local-development-postgres-url>' go test ./internal/rbac -run TestPostgresRBAC -v
```

The suite creates a fresh isolated schema, excludes `public` from its search path,
verifies the current schema, applies existing migrations only there, and cleans
up only that schema. It exercises bootstrap, permission unions, delegation limits,
revocation, tenant isolation, account status, audited rollback, and real HTTP
login/JWT/RBAC/service/repository flows. No fake granting policy is used in the
Phase 4 HTTP tests. Unit tests also verify fail-closed policy behavior and all 14
new route authentication boundaries. Without the opt-in URL PostgreSQL tests skip.
Production-scale load and race-detector testing are not included.

## Verify

```sh
gofmt -w cmd internal
go mod tidy
go build ./...
go test ./...
```

Unit tests cover bcrypt verification, JWT claims/signatures, middleware identity,
request validation, non-enumerating login errors, rotation, and logout. PostgreSQL
integration tests are opt-in:

```sh
AUTH_TEST_DATABASE_URL='<development-postgres-url>' go test ./internal/auth -run TestPostgresAuthentication -v
```

The database role must be allowed to create schemas. Tests create a unique private
schema, apply the existing migration there, and drop only that test schema on
cleanup. Existing application tables and data are untouched. These tests verify
concurrent single use, rollback on failed replacement insertion/issuance, expiry,
revocation, account validity, email case handling, tenant selection, audits, the
HTTP login/refresh/logout flow, and development seed opt-in/idempotency.
Without `AUTH_TEST_DATABASE_URL`, the integration test is skipped.

On minimal environments without C headers, prefix build/test/run commands with
`CGO_ENABLED=0`. If a workspace contains an empty `.git` directory, also use
`GOFLAGS=-buildvcs=false` to disable repository metadata stamping.

## Interactive Swagger documentation

Set `APP_ENV=development` in the local `.env`, restart the API, then open
[http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html).
The existing local `.env` is preserved; only the non-secret development flag is
added if absent. Process environment variables still override `.env`.

`APP_ENV` defaults to `production` when absent; supported values are `development`,
`test`, `staging` and `production`. Swagger routes are registered by default **only**
in development. `SWAGGER_ENABLED=false` disables them even in development;
`SWAGGER_ENABLED=true` explicitly enables them in any environment. Invalid values
fail configuration validation. Outside development, keep the override unset/false.
The UI, embedded spec and assets all return 404 when disabled. Swagger is not an
additional authenticated application endpoint; limit access when explicitly enabled.

Click **Authorize** and enter the complete value `Bearer <access JWT>`. Swagger
2.0 represents bearer JWT as an API-key scheme in the `Authorization` header.
Do not enter a refresh token there: refresh/logout take `refresh_token` in JSON.
Login requires `email`, `password` and `tenant_code`. Browser authorization is not
persisted to local storage. Clear authorization and close the browser when done.
**Try it out sends real requests**: writes change records and create audit history.
No credentials or tokens belong in committed examples or captured terminal output.

All 30 application operations include request/response models, parameters,
response statuses and permission descriptions. There is no audit-query endpoint;
audit side effects are documented on the operations that actually record them.
The wildcard documentation route is excluded from the application inventory.

Annotations live beside handlers and DTOs. The Go tool dependency pins
`github.com/swaggo/swag/cmd/swag` to the module version; gin-swagger serves the UI
with swaggerFiles assets. Regenerate after annotations or DTOs change:

```sh
sh scripts/generate-swagger.sh
go test ./internal/config ./internal/server -run 'TestSwagger' -v
go build ./...
go test ./...
go vet ./...
```

Commit `docs/swagger/docs.go`, `swagger.json` and `swagger.yaml` together. Generation
produces Swagger/OpenAPI **2.0**, replacing the previous standalone OpenAPI 3
artifact and Python generators. The Go spec is embedded into the binary: regenerate
and rebuild/restart the API to publish annotation changes. No Python packages or
global `swag` installation are required. Contract tests compare real Gin routes,
methods, JWT security, permission metadata and DTO fields with the generated spec;
HTTP tests verify embedded assets/spec exposure and the production-off boundary.

## Phase 5 documentation validation and safety

```sh
gofmt -w cmd internal docs/swagger
go mod tidy
sh scripts/generate-swagger.sh
go build ./...
go test ./...
go vet ./...
# Optional on a host with CGO and C development headers:
go test -race ./...
```

For a documentation-only pass, keep `AUTH_TEST_DATABASE_URL`,
`PHASE3_TEST_DATABASE_URL` and `RBAC_TEST_DATABASE_URL` unset. Opt-in integration
tests create/drop test schemas and must not run under a no-database-mutation
instruction. Prior successful integration/live results are historical evidence,
not Phase 5 reruns. See the validation report for exact flags/results.

The ignore file excludes secrets, captures, binaries, IDE state and temporary
reports while keeping submission docs and `.env.example` visible. It cannot
remove already tracked files or history. This workspace has unusable `.git`
metadata: staged/committed/history secret review remains unverified. Check
`git status`, `git diff --cached`, `git ls-files` and secret history in the real
submission repository before publishing.

The public development credential/seed account, lack of production rate limiting,
TLS/ingress, MFA/lockout, JTI logout invalidation, token-family replay defense,
last-admin recovery and audit tamper evidence remain explicit limitations. No
production-readiness or performance guarantee is claimed.

## Phase 6: revision-based permission cache

The cache uses a bounded 1,024-entry LRU per policy/API instance. Keys include
tenant, user and authoritative tenant revision; both granted and empty permission
unions are cached. Every check still verifies current identity and revision from
primary PostgreSQL. Independent instances need no Redis, TTL or notifications for
revocation. Cache population reads grants and revision in one statement snapshot.
See [design and trade-offs](docs/design.md#phase-6-authoritative-permission-caching).

Migration 003 is additive and must be applied **once**, with operator approval,
after 001/002 and before starting the new API build. It adds the revision counter
and transactional invalidation triggers; it does not delete records or audit logs.
DDL requires an owner/migration role and briefly locks the affected tables. Use a
quiet deployment window. Do not reset revisions or disable the triggers. API
startup does not migrate; missing 003 causes protected checks to fail closed.

Read-only preflight (003 must be absent before applying it):

```sql
SELECT column_name, data_type, column_default, is_nullable
FROM information_schema.columns
WHERE table_schema='public' AND table_name='tenants'
  AND column_name='authorization_revision';
SELECT column_name FROM information_schema.columns
WHERE table_schema='public' AND table_name='tenant_users'
  AND column_name IN ('removed_at','updated_at');
```

After approval, with the existing local Compose migration role:

```sh
# 003 contains BEGIN/COMMIT; do not wrap it in another transaction.
docker compose exec -T \
  -e PGOPTIONS='-c search_path=public -c lock_timeout=5s -c statement_timeout=60s' \
  postgres psql -X -U app -d multitenant -v ON_ERROR_STOP=1 \
  -f - < migrations/003_authorization_revision.sql
```

Read-only verification:

```sql
SELECT id, authorization_revision FROM public.tenants ORDER BY id;
SELECT c.relname AS table_name, t.tgname, t.tgenabled
FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND NOT t.tgisinternal
  AND t.tgname LIKE '%authorization_revision' ORDER BY c.relname,t.tgname;
```

Expect seven enabled triggers and a non-null, nonnegative BIGINT revision. Existing
tenants start at zero until a tracked change; counters do not change profile
`updated_at`. After migration, rebuild/restart the API; no JWT replacement is
required. Leave migration 003 unapplied to development until explicitly approved.

```sh
go mod tidy
go build ./...
go test ./...
go vet ./...
# Only with an approved local development test DSN: unique schemas are created
# and removed; public application tables are excluded by the RBAC harness.
RBAC_TEST_DATABASE_URL='<local-development-postgres-url>' \
  go test ./internal/rbac -run 'TestPostgres(RBAC|PermissionCache)' -count=1 -v
```
