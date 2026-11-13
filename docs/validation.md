# Phase 5 Swagger validation report

Validated on 2026-11-13 against the current source. No migration, SQL mutation,
seed, bootstrap, login, refresh, logout or management write was executed. Startup
and readiness ping PostgreSQL read-only. Application records and audit history are
preserved; both migrations retain their recorded fingerprints.

## Actual results

| Check | Result |
|---|---|
| `gofmt -w cmd internal docs/swagger` | Exit 0 |
| `go mod tidy` | Exit 0; Swaggo runtime/tool dependencies pinned in go.mod/go.sum |
| `sh scripts/generate-swagger.sh` | Exit 0; generated Go, JSON and YAML artifacts |
| `go build ./...` | Exit 0 |
| `go test ./...` | Exit 0; DB integration opt-ins explicitly unset |
| `go vet ./...` | Exit 0; no diagnostics |
| `go test ./internal/server -run TestSwagger -v` | Exit 0; route/method/security/permission contracts, 23 DTO field sets, artifact/reference checks and enabled/disabled UI/spec/assets tests pass |
| Generated JSON/YAML check | Equivalent Swagger 2.0 documents: 30 operations, 19 paths, 26 definitions, 183 resolved local references; no password_hash/token_hash properties |
| Live `GET /swagger/index.html` | HTTP 200 |
| Live `GET /swagger/doc.json` | HTTP 200; paths, definitions, security and 20-permission catalog match current generated source |
| Live `GET /swagger/swagger-initializer.js` | HTTP 200; authorization persistence disabled; external validator disabled |
| Live `GET /swagger/swagger-ui-bundle.js` and `/swagger/swagger-ui.css` | HTTP 200 for each |
| Live `GET /health` and `/ready` | HTTP 200 for each |
| Production-disabled documentation | In-process HTTP tests: HTML, JSON and assets return 404 when disabled; config tests confirm production/staging/test/unset environment defaults off, development defaults on, explicit overrides and invalid-input handling |
| Undocumented application operations | **None**; actual Gin registry matches all 30 operations, excluding `/swagger/*any` |

The initial targeted run found permission-catalog metadata nested under the
security scheme instead of the root. Its annotation placement was corrected,
documentation regenerated and tests rerun successfully. The obsolete standalone
OpenAPI artifact and Python generators were removed after the replacement route
and UI tests passed.

## Reproducing validation

The Go tool declaration pins `github.com/swaggo/swag/cmd/swag`; generation uses
`go tool swag init` through the checked-in shell script. No global tool or Python
installation is required for generation or Go contract tests. An additional local
Python/PyYAML comparison also verified generated JSON/YAML equivalence.

On this runner commands use:

```sh
export GOCACHE=/tmp/multitenant-go-build
export GOMODCACHE=/tmp/multitenant-go-mod
export CGO_ENABLED=0
export GOFLAGS=-buildvcs=false
unset AUTH_TEST_DATABASE_URL PHASE3_TEST_DATABASE_URL RBAC_TEST_DATABASE_URL

gofmt -w cmd internal docs/swagger
go mod tidy
sh scripts/generate-swagger.sh
go build ./...
go test ./...
go vet ./...
go test ./internal/server -run TestSwagger -v
```

CGO is disabled because this environment lacks C development headers. VCS
stamping is disabled because this workspace is not a usable Git repository.
The race detector was not rerun for this Swagger update; the earlier Phase 5
probe found missing `stdlib.h`/`pthread.h`, and `-race` requires CGO. No race or
performance result is claimed.

## Scope and limitations

- No process was listening on port 8080 at inspection. The updated API binary was
  built from this workspace and started using the existing local configuration.
  Only documentation/probe GETs were sent. Its served specification matches the
  generated source. Browser rendering and Try-it-out mutations were not exercised.
- Swagger 2.0 represents bearer JWT using an API-key security definition. Enter
  the full `Bearer <access JWT>` in **Authorize**. Refresh/logout authenticate the
  opaque token in JSON, not that header. Authorization persistence is disabled;
  tokens used manually still exist in browser memory and may appear in devtools.
- Swagger routes are disabled outside development by default. An explicit true
  override exposes them without authentication; restrict access if enabled in a
  shared environment. The existing local HTTP bind setting is preserved.
- Contract tests check actual route/method inventory, unique operation IDs,
  security and source permission metadata, model field sets, required path
  parameters, local references, JSON/YAML consistency and embedded spec consistency.
  They are not an official external Swagger-schema validator or proof that every
  HTTP error branch has been executed. No OpenAPI 3 validation is claimed for the
  replacement Swagger 2.0 artifacts.
- PostgreSQL integration suites were not rerun: they create/drop private schemas
  and require separate authorization under the no-database-mutation constraint.
  Authentication and RBAC logic remain unchanged by this documentation update.
- There is no audit search/export endpoint; actual audit-producing operations are
  described. There is no public user/tenant registration or HTTP administrator
  bootstrap. Documentation adds no business operations.
- `docs/design.md`, `docs/erd.md` and `docs/requirements-checklist.md` are retained.
  Existing production limitations (development fixtures/credentials, no production
  ingress/rate limiting/MFA, JWT logout invalidation, refresh-family replay defense,
  last-admin recovery and audit tamper evidence) remain documented there.
- Git status/diff/history review is unavailable because `.git` is unusable in this
  workspace. Ignore rules do not prove secrets were never committed. Review the
  actual submission repository before publishing; no credentials/tokens were
  printed during this update.

## Preserved migration fingerprints

```text
001_init.sql
02eca93494c8bcfcefaf162cbf2e61da6caa541a4a0264dad1eddb3af04d34cf

002_membership_lifecycle.sql
9ecd6bd88b1c0f227854f02fdc334e6953b8513b612ca939274089b8bad035be
```
