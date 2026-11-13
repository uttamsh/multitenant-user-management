# Phase 7: API container validation

Work is on `feature/phase-7-docker-api`; no commit, push or merge is performed.
The existing PostgreSQL service and volume definitions match the pre-change
`HEAD` exactly, including credential, loopback port, persistence and health check.
No migration, seed, bootstrap or application-record mutation is part of this task.

## Implementation

- `Dockerfile`: Go 1.26 multi-stage static builds; non-root UID/GID 65532 scratch
  runtime, CA roots, readiness probe and direct SIGTERM-aware API entrypoint.
- `.dockerignore`: excludes Git metadata, `.env` files, credentials, backups,
  database dumps, captures, build outputs, editor state and temporary artifacts.
- `compose.yaml`: API service with PostgreSQL DNS, healthy dependency, loopback
  publication, restart policy, readiness check, read-only root filesystem,
  dropped capabilities, no-new-privileges and graceful stop window.
- `.env.example`: separate container database URL and optional published port/stop
  grace settings. A missing container URL was added privately to local `.env`
  using the existing credentials and hostname `postgres`; no existing values were
  overwritten and no secrets were printed.
- `cmd/healthcheck/main.go`: readiness probe without adding a runtime shell/curl.
- `internal/database/schema.go`, `schema_test.go`, `cmd/api/main.go`: bounded,
  read-only startup verification of the non-null BIGINT revision column and all
  seven enabled revision triggers. Missing schema stops startup; no migration runs.
- `scripts/validate-docker.py`: read-only Compose/image contracts using Python's
  standard library; resolved credential values are never printed.
- `README.md` and `docs/design.md`: Docker/local development, explicit migration,
  secrets, logs, health, shutdown and deployment trade-offs.

## Validation results

| Check | Result |
|---|---|
| `docker compose config --quiet` | Exit 0; resolved secrets suppressed |
| `python3 scripts/validate-docker.py` | Exit 0; Go version, service database hostname, loopback port, dependency and hardening checks passed |
| `gofmt` | Completed on changed Go files |
| `go test ./...` | Exit 0; existing tests and new schema guard tests passed; PostgreSQL integration opt-ins unset |
| `go build ./...` | Exit 0 |
| `go vet ./...` | Exit 0 |
| `git diff --check` | Exit 0 |
| `docker compose build api` | Exit 0; BuildKit completed successfully; Compose emitted a non-blocking warning that buildx/Bake was unavailable |
| `python3 scripts/validate-docker.py --image` | Exit 0; UID/GID 65532, direct entrypoint, readiness healthcheck and no baked credential environment verified |
| Runtime image | 14,906,377 bytes; image ID `sha256:f60df217b586da08d26c6bacda0ef6a6438b21908b31ff43209bcc54cdf11b6c` |
| Approved handover | Workspace host API exited after SIGTERM; no force kill; container now owns loopback 8080 |
| `docker compose up -d --no-recreate` | Exit 0; existing PostgreSQL left running; only new API container created |
| `docker compose ps` | PostgreSQL and API running and healthy |
| Host curl `/health`, `/ready`, `/swagger/index.html` | HTTP 200 for each from the container API |
| Host curl `/api/v1/users` without JWT | HTTP 401 |
| Running API inspection | UID/GID 65532, read-only root, ALL capabilities dropped, PostgreSQL service DNS, loopback port, no host mounts |
| PostgreSQL preservation | Container ID, original start time and volume attachment exactly match recorded pre-start values; not recreated or restarted |

The Compose environment resolves to development with no explicit Swagger override,
so existing configuration enables Swagger. Production defaults remain off. The
image itself defaults to production; no JWT secret/database DSN is baked in.

Commands used for Go validation set `CGO_ENABLED=0` and temporary Go caches.
No new Go dependency is required. No integration, race, load, vulnerability scan
or image-signing result is claimed for this phase.

## Deployment limits

Migration 003 must be applied manually with approval before the new API starts.
It was previously applied to the local database; do not rerun it. A healthy
PostgreSQL container alone does not prove schema/credential readiness, hence the
API startup guard. Its check does not replace trusted migration management or
verify arbitrary trigger function bodies against a cryptographic manifest.

The Go minor image tag tracks patches rather than an immutable digest. Record
reviewed digests in a release pipeline. Scratch has no interactive diagnostic
shell; use host curl, Docker health status and stdout logs. Docker operators can
inspect runtime environment secrets. Local DB credentials/TLS settings remain
development-only. Readiness failures mark the API unhealthy; Docker restart
policy handles process exit, not every unhealthy state.

The user approved gracefully stopping the host API and starting the container
on 8080. The original host process exited after SIGTERM. `--no-recreate` protected
existing containers, and PostgreSQL container identity, original start time and
volume attachment were verified unchanged. The Docker API remains running; a
future switch back to local `go run` requires stopping only the API container first. Never delete volumes
or reset data as part of deployment validation.

## Final state

Image `multitenant-user-management-api:local` is running on
`127.0.0.1:8080`, including development Swagger UI. No migrations, application
records or audit history were changed, and no volumes were deleted. Migrations
001/002/003 have no Git diff. Only health/readiness/documentation and missing-JWT
HTTP requests were made; there was no live login or management mutation.

The build emitted a non-blocking buildx/Bake warning and used the Docker driver
successfully. Tests deliberately excluded PostgreSQL integration opt-ins to avoid
creating test data during this deployment-only phase. Authentication/RBAC behavior
is covered by existing unit/contract tests here; prior live/integration evidence
remains historical, not a new authenticated container smoke test.
