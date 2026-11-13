# Phase 6 validation

Implemented on `feature/phase-6-rbac-cache` after explicit branch selection.
Nothing was committed or pushed. Migrations 001/002 are unchanged. Migration 003
was applied only inside unique test schemas; it was not applied to `public`.
The running development API was not restarted with this unapplied migration.

## Changed files

- `migrations/003_authorization_revision.sql`: additive counter, constraint and
  seven transactional invalidation triggers.
- `internal/rbac/policy.go`: live database revision/identity probe, permission
  cache lookup and population; existing transaction checks remain uncached.
- `internal/rbac/cache.go`: bounded, mutex-protected LRU and immutable bitsets.
- `internal/rbac/permission_source.go`: primary database probes and single-statement
  coherent permission snapshots.
- `internal/rbac/cache_test.go`: focused cache, isolation and failure unit tests.
- `internal/rbac/cache_integration_test.go`: isolated PostgreSQL/HTTP cache tests.
- `README.md`, `docs/design.md`, `docs/erd.md`,
  `docs/requirements-checklist.md`, `docs/phase6-validation.md`: setup, migration,
  schema, security, concurrency, trade-offs and actual validation evidence.

## Actual results

| Command/check | Result |
|---|---|
| `gofmt -w` on changed Go files | Exit 0 |
| `go mod tidy` | Exit 0; no dependency changes |
| `go build ./...` | Exit 0 |
| `go vet ./...` | Exit 0; no diagnostics |
| `go test ./internal/rbac` without integration opt-ins | Exit 0 |
| Full `go test ./... -count=1`, with all three integration opt-ins | Exit 0; auth, Phase 3, existing RBAC and new permission-cache PostgreSQL suites executed |
| Focused PostgreSQL permission-cache suite | Exit 0; initial sandbox-blocked connection was rerun with local database access allowed |
| Swagger route/DTO/permission contract tests | Passed as part of full suite; all 30 application operations remain documented |
| `git diff --check` | Exit 0 |
| Initial `CGO_ENABLED=1 go test -race ./internal/rbac` attempt | Historical runner limitation: exit 1 during build because C development headers were missing. Superseded by the successful user-reported runs below. |
| `CGO_ENABLED=1 go test -race ./... -count=1` | **PASS — reported by the user on 2026-11-13; not rerun by the reviewing agent.** |
| `CGO_ENABLED=1 go test -race ./internal/rbac -count=5` | **PASS — reported by the user on 2026-11-13; not rerun by the reviewing agent.** |
| Read-only development DB inspection | Database `multitenant`; `public.tenants.authorization_revision` absent; no auth/Phase 3/RBAC test schemas remained after cleanup |

During the initial agent validation, Go reported `go1.26.8 linux/amd64`. Successful Go commands used
`CGO_ENABLED=0`, `GOCACHE=/tmp/multitenant-go-build` and
`GOMODCACHE=/tmp/multitenant-go-mod`. No VCS override was needed on this branch.
No timing result is presented as a throughput or cache performance measurement.
The later successful race runs used `CGO_ENABLED=1` as shown above. Their toolchain
details and database integration opt-ins were not supplied; these passes must not
be interpreted as proof that PostgreSQL suites ran with race instrumentation.
The prior separately recorded PostgreSQL integration run remains the evidence
for database behavior. Passing race detection covers exercised paths and does
not prove the absence of every possible race or transaction anomaly.

## Test coverage

- Unit tests check cold/warm positive and empty permission sets, grant after
  cached denial, revocation across two caches, same-user/different-tenant keys,
  concurrent population, strict LRU bounds, eviction, live DB probes, validity
  rejection, population failures and permission-bitset catalog capacity.
- A population test changes the revision between the first database probe and
  the snapshot fetch, verifying that grants use the snapshot's own revision.
- PostgreSQL tests use the existing RBAC unique-schema harness with all migration
  files and no `public` fallback. They exercise the same access JWT across
  `403 -> 200 -> 403` transitions through two independently cached policies,
  permission removal/regrant, assignment removal/regrant and role deletion.
- Additional cases cover parallel PostgreSQL-backed population, uncommitted
  grant changes invisible to another connection, transaction/audit failure
  rolling back the revision, both bootstrap modes, role profile changes and
  global permission-identifier invalidation across linked tenants.
- Warm cached actors are denied after tenant/membership suspension, membership
  removal and user deletion. A closed PostgreSQL pool cannot authorize a warm
  cached permission.
- Existing integration suites also exercise cross-tenant 404s, missing JWT 401s,
  ordinary member 403s, delegation, current-transaction permission rechecks,
  membership lifecycle, soft deletion, authentication and refresh rotation.

## Reproduction

```sh
gofmt -w internal/rbac/cache.go internal/rbac/cache_test.go \
  internal/rbac/cache_integration_test.go internal/rbac/permission_source.go \
  internal/rbac/policy.go
go mod tidy
go build ./...
go test ./...
go vet ./...
# On a host with the required C toolchain/headers:
CGO_ENABLED=1 go test -race ./... -count=1
CGO_ENABLED=1 go test -race ./internal/rbac -count=5
```

To actually execute PostgreSQL tests, set `AUTH_TEST_DATABASE_URL`,
`PHASE3_TEST_DATABASE_URL` and `RBAC_TEST_DATABASE_URL` privately to an authorized
local development DSN, then run `go test ./... -count=1`. The DSN is not shown
here or in test output. The role needs permission to create/drop isolated test
schemas. Never substitute a production DSN. Existing application rows are not
fixtures and must not be changed. Migration/deployment instructions and read-only
verification queries are in the README Phase 6 section.

## Concurrency and deployment limits

The cache mutex protects entries and LRU state; cached values are immutable
bitsets. Concurrent misses may duplicate database work. Each miss reads the
revision and permission union in one SQL statement snapshot; late old fills have
old keys. Every later check reads PostgreSQL again, so an old cache entry cannot
survive a committed revision change as an authorization result. Checks already
in flight may finish with their pre-commit snapshot. Transaction checks bypass
the cache under the existing tenant locks.

Row triggers conservatively invalidate entire tenants and can increment the
revision more than once per transaction. They add writes and locking; trusted
multi-tenant SQL writers can still deadlock and must retry after conflict. Do not
disable triggers, reset counters or use replica reads for authorization. API
instances must be restarted after a database restore or catalog change. No
external notification, TTL, Redis, throughput guarantee or race-freedom claim is
required or made.

## Final pre-migration security review

Reviewed on 2026-11-13. Only this validation document was edited during the review.
No migration was applied, no application data was changed, and no commit, push or
merge was performed. **No blocking defect was identified in the current supported
application workflows.** This conclusion is conditional on the deployment and
trusted-database boundaries below, rather than permission to apply the migration.

| Area | Review result and source evidence |
|---|---|
| Trigger coverage | Seven triggers cover role, role-permission, user-role and membership INSERT/UPDATE/DELETE; tenant status; user deletion/restoration state; and permission resource/action changes. Moving a relationship between tenants bumps both old and new tenants. See `003_authorization_revision.sql:10`, `:25`, `:34`, `:48`, `:63`. Bootstrap uses the same covered DML in its existing audit transaction (`internal/rbac/bootstrap.go:92`). |
| Deletes and cascades | Migration 001 and read-only inspection of the actual public schema confirm all ten FKs use `NO ACTION` and are validated; there are no implicit FK deletion cascades. Role deletion explicitly audits and deletes user-role links, permission links and the role in one transaction (`internal/rbac/repository.go:110`); each DELETE fires a revision trigger. Referenced permissions/users cannot be physically deleted while dependent rows remain. Membership removal/user soft deletion use covered UPDATE paths. Migration 003 neither adds cascades nor deletes history. |
| Revision consistency | Atomic `revision = revision + 1` updates serialize on tenant rows. Related changes and revisions become visible together at commit. Membership/role profile changes conservatively invalidate even when rights are unchanged. Multiple increments in one transaction are harmless. Nonnegative constraint and BIGINT overflow reject invalid/overflowing counter changes; counters must never be reset by operators. |
| Rollback and audit safety | Triggers execute inside the existing mutation transaction, including bootstrap. Existing `access.Scoped` rollback/commit and transactional audit writes remain unchanged (`internal/access/access.go:104`, `:150`). Earlier integration tests verify explicit rollback and audit-failure rollback leave the revision unchanged (`internal/rbac/cache_integration_test.go:124`). Direct administrative SQL must still follow the audit protocol; triggers enforce invalidation, not audit event creation. |
| Concurrent population/authorization | Every valid supported policy check first reads current identity validity and revision. A miss loads revision and grants in a single SQL statement snapshot and uses that returned revision as the key (`internal/rbac/permission_source.go:25`, `:31`). An old late fill cannot overwrite a different revision's entry. Mutex-protected LRU operations return immutable values (`internal/rbac/cache.go:64`). Transaction checks and delegation checks still query grants directly under existing locks (`internal/rbac/policy.go:54`). |
| Tenant isolation/failure handling | JWT middleware alone supplies trusted identity; policy validates UUIDs and uses parameterized tenant/user predicates in both live probes and grant queries. Cache keys include canonical tenant/user IDs and revision. Database errors and invalid/inactive identities cannot use a cached allow. Existing 401/403 and tenant-scoped target 404 behavior remain intact. |
| Existing-data compatibility | The new BIGINT column has a zero default and does not change tenant profile `updated_at`, IDs, grants, JWTs, password hashes or audit history. Existing queries use explicit tenant columns. Migrations 001/002 retain their hashes. Older application code can operate against the additive schema; the new cache policy requires 003 first and fails closed without it. |

Read-only local database preflight confirmed:

- Database `multitenant`, role `app`, transaction read-only enabled.
- `public.tenants.authorization_revision` is still absent.
- None of the four new trigger-function names already exist in `public`.
- All ten existing public FK constraints are validated and use `NO ACTION`.
- The inspected `app` role has UPDATE privilege on `public.tenants`.

Before deployment, apply once through the documented command with explicit
`search_path=public`, lock/statement timeouts, `ON_ERROR_STOP` and migration 003's
own transaction. The functions capture the creation-time search path; do not apply
from an uncontrolled path. Use an owner/migration role, then verify all seven
triggers are enabled. Runtime roles need tenant revision update rights because
the functions run with invoker privileges, not `SECURITY DEFINER`. Apply 003 before
starting the new cache-enabled API and use the authoritative primary database.

Non-blocking limitations and follow-ups:

- TRUNCATE, disabled triggers/replication-role bypass, counter resets and tenant
  UUID reuse are outside the supported mutation protocol. Do not grant these
  powers to an untrusted runtime role. Schema owners/superusers remain trusted;
  this migration is not a defense against arbitrary privileged SQL. Restart all
  API instances after database restore or catalog changes.
- The nonnegative check does not enforce monotonicity against arbitrary explicit
  SQL assignments to the revision. A restricted counter-write mechanism would be
  additional hardening if runtime SQL writers cannot be trusted.
- Statements already in flight may complete using a pre-revocation snapshot.
  This does not allow subsequent checks to reuse the old revision; mutation
  transaction rechecks remain authoritative. There is no retroactive cancellation.
- Broad per-tenant invalidation and row triggers add writes/contention. Multi-row
  or cross-tenant SQL can deadlock despite sorted fan-out locks; PostgreSQL aborts
  a participant, and the existing conflict handling rolls it back for retry.
- Existing tests exercise explicit relationship deletion, not a future schema
  with `ON DELETE CASCADE`. Cascade/schema changes, tenant transfers, maintenance
  operations and new permission-affecting tables need their own regression tests
  before being introduced. Race-detector passes do not replace those tests.

Preserved SHA-256 fingerprints:

```text
001_init.sql
02eca93494c8bcfcefaf162cbf2e61da6caa541a4a0264dad1eddb3af04d34cf
002_membership_lifecycle.sql
9ecd6bd88b1c0f227854f02fdc334e6953b8513b612ca939274089b8bad035be
```
