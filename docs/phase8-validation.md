# Phase 8: login audit completeness

Implemented on `feature/phase-8-login-audit`. No commit, push, merge, production
deployment, migration or development-record mutation is performed. The running
Phase 7 image is not rebuilt/replaced by this task; deployment of this change is
a separate reviewed step. No new migration is required.

## Exact semantics

After password verification, `CreateSession` revalidates/locks the existing user,
tenant and membership validity rows, inserts the refresh credential's SHA-256
hash, inserts the required success audit, and commits the existing transaction.
The service returns credentials only after that commit succeeds. Rotation still
uses the existing lower-level session insert and does not create new login events.

| Field | Successful login | Failed credential/account check reaching the service |
|---|---|---|
| `action` | `auth.login.success` | `auth.login.failure` |
| `tenant_id` | Verified tenant ID | NULL |
| `actor_id` | Authenticated user ID | NULL |
| `target_type` | `user` | NULL |
| `target_id` | Authenticated user ID | NULL |
| `created_at` | Existing PostgreSQL `DEFAULT NOW()` transaction timestamp | Existing PostgreSQL `DEFAULT NOW()` timestamp |
| `metadata` | Existing empty JSON object default | Existing empty JSON object default |
| Persistence | Required, atomic with the new refresh session | Best effort, bounded, survives request cancellation |

No password, submitted email, access JWT, refresh token or token hash is written
to an audit event. Only refresh_tokens retains the refresh hash. The failure-only
repository method accepts no identity, action or request-data parameters, so it
cannot accidentally assert an unverified actor or target.

Session insertion, audit insertion or transaction errors return an empty token
pair. An audit insertion failure rolls back the inserted session; an insertion
failure cannot leave an orphan success audit. HTTP persistence errors remain a
sanitized 500 without tokens or driver diagnostics. Invalid credentials retain
the same non-enumerating 401 even when failure-audit persistence is unavailable.
Malformed JSON/invalid DTO requests rejected before the service retain existing
400 behavior and are not newly audited.

JWT format/validation, refresh rotation, logout, RBAC/cache checks, tenant scoping,
401/403 behavior, migrations and Phase 7 Docker/startup guard are unchanged. No
tenant reactivation feature or historical audit backfill was added.

## Changed files

- `internal/auth/repository.go`: required success insert in the existing session
  transaction; fixed anonymous failure insert.
- `internal/auth/service.go`, `models.go`: remove detached success logging;
  document the atomic repository contract; narrow failure auditing API.
- `internal/auth/service_test.go`, `handler_test.go`: persistence failure returns
  no credentials/session, success identity, uniform failures, safe logging and
  request-cancellation-independent best-effort failure auditing.
- `internal/auth/login_audit_integration_test.go`: real PostgreSQL audit fields,
  session consistency, session/audit failure rollback, HTTP 500 without tokens,
  and anonymous invalid-password/unknown-account/wrong-tenant events.
- `internal/auth/repository_integration_test.go`: run these cases in the existing
  unique-schema harness; exclude public from parent/seed-child search paths;
  compare audit-count deltas now that direct fresh-session fixture creation is
  audited; allow a bounded longer deadline for the additional integration cases.
- `internal/auth/handler.go`, `cmd/api/main.go`, `docs/swagger/{docs.go,swagger.json,swagger.yaml}`:
  update/regenerate descriptions for the actual new audit behavior; no API routes
  or wire models change.
- `README.md`, `docs/design.md`, `docs/requirements-checklist.md`, this report:
  document the changed behavior, assignment evidence and practical limits.

## Validation

| Check | Actual result |
|---|---|
| `gofmt` on changed Go files | Completed |
| `go build ./...` | Exit 0 |
| `go test ./...` with integration opt-ins unset | Exit 0 |
| `go vet ./...` | Exit 0, no diagnostics |
| `go test ./internal/auth -run TestPostgresAuthentication -count=1 -v` with isolated-schema DSN | Exit 0; new login-audit subtests and existing login/refresh/logout/seed tests passed |
| `CGO_ENABLED=1 go test -race ./... -count=1` with all three PostgreSQL integration opt-ins | Exit 0; authentication, user and RBAC integration suites executed in unique schemas under the race detector |
| `sh scripts/generate-swagger.sh` | Exit 0; generated Go/JSON/YAML documentation |
| Swagger route/DTO/security/permission contracts | Passed in `go test ./...`; all 30 application operations remain documented |
| `git diff --check` | Exit 0 |
| Read-only cleanup verification | Zero remaining auth/user/RBAC test schemas and zero audit-failure test functions leaked into public |

Go reports `go1.26.8 linux/amd64`. Ordinary build/test/vet/generation commands use
`CGO_ENABLED=0` and caches under `/tmp`. The race run uses `CGO_ENABLED=1`; the C
header probe succeeded on this host. PostgreSQL tests receive the existing local
DSN privately; no credentials or generated tokens are displayed.

The auth harness creates its own unique schema and excludes public entirely. Its
child seed process receives the same explicit private-schema search path. Other
PostgreSQL suites retain their own unique schemas. Existing migration files are
used only to initialize these private test schemas, which are removed on cleanup;
no migration is applied to the development application schema.

## Reproduction and limits

```sh
gofmt -w internal/auth cmd/api/main.go docs/swagger
sh scripts/generate-swagger.sh
go build ./...
go test ./...
go vet ./...
# Set AUTH_TEST_DATABASE_URL, PHASE3_TEST_DATABASE_URL and RBAC_TEST_DATABASE_URL
# privately to an approved local development DSN to execute isolated DB suites:
CGO_ENABLED=1 go test -race ./... -count=1
```

Successful-login audit completeness can be marked **PASS for new logins**:
verified tenant, actor, user target and database timestamp are persisted atomically
with the session. Safe anonymous failure logging remains best effort by design.
Existing historical rows with missing target fields are not modified.

A lost connection during COMMIT can make its outcome uncertain to the client.
The service returns no credentials on any reported commit error, while PostgreSQL
keeps audit and session atomic. This is not an exactly-once delivery/idempotency
mechanism, proof that a client received credentials, a complete security-event
stream or tamper-evident audit storage. Refresh/logout audit coverage is unchanged.
