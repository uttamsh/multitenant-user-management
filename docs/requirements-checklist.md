# Requirements checklist and evidence

## Scope and status meanings

No original assignment PDF, rubric or separate requirements file was found in the
workspace. This checklist maps the **supplied Phase 1–5 instructions** to actual
source and tests. It cannot certify compliance with an unseen formal assignment.
There is no inferred requirement for endpoints absent from the supplied scope.

- **Complete**: implemented/documented with the evidence linked below. This does
  not mean every failure branch, production deployment or performance property
  has been tested.
- **Partial**: useful implementation/evidence exists, with a specific limit.
- **Missing**: the artifact/control is not present; no implementation is claimed.

Current execution results are in [validation.md](validation.md). PostgreSQL tests
are opt-in and were not rerun during the database-read-only Phase 5 task. Their
presence is evidence of test coverage, not a claim of a current execution.

## Application requirements

| Requirement | Status | Source/test evidence and limits |
|---|---|---|
| Go 1.26, Gin, pgxpool and PostgreSQL 16 | Complete | [go.mod](../go.mod), [Compose](../compose.yaml), [startup](../cmd/api/main.go) |
| Modular configuration/database/middleware and graceful shutdown | Complete | [config](../internal/config/config.go), [pool](../internal/database/database.go), [middleware](../internal/middleware/middleware.go), startup |
| Optional `.env`, existing environment wins, no real secrets in template | Complete | [loader tests](../internal/config/config_test.go), [.env.example](../.env.example) |
| Application liveness and database readiness | Complete | [router](../internal/server/router.go), [probe tests](../internal/server/router_test.go) |
| Consistent application JSON errors and request logging | Complete | [HTTP helpers](../internal/httpapi/http.go), middleware, recovery/logging tests. Transport errors and already-written responses are exceptions. |
| Preserve original migrations and application data | Complete | [001](../migrations/001_init.sql), [002](../migrations/002_membership_lifecycle.sql); unchanged checksums recorded in validation. No DB commands ran in Phase 5. |
| Handler → service → repository separation | Complete | [auth](../internal/auth/handler.go), [tenant](../internal/tenant/service.go), [user](../internal/user/repository.go), [RBAC](../internal/rbac/repository.go) |
| Tenant email/password login, consistent normalization and active account checks | Complete | [auth service](../internal/auth/service.go), [SQL](../internal/auth/repository.go), [unit tests](../internal/auth/service_test.go). Schema has no user status field: non-deleted user is required. |
| bcrypt verification and password hashing without hash disclosure | Complete | Auth/user services; [password-boundary tests](../internal/user/service_test.go); DTOs contain no response hash. |
| Short-lived signed access JWT with required claims/algorithm/issuer validation | Complete | [tokens](../internal/auth/token.go), [claims/signature tests](../internal/auth/token_test.go) |
| Opaque random refresh credentials stored only as SHA-256 hashes | Complete | Token utilities and auth repository; token issuance/format tests |
| Atomic rotation, expiry/revocation, concurrent single use and rollback | Complete | Auth repository; [PostgreSQL auth tests](../internal/auth/repository_integration_test.go) |
| Logout revokes refresh credential | Complete | Auth handler/service/repository. Already-issued JWTs and other sessions are not revoked. |
| Trusted identity only from validated JWT; tenant headers/body/query never select scope | Complete | [JWT middleware](../internal/auth/middleware.go), [policy](../internal/rbac/policy.go), [isolation tests](../internal/user/repository_integration_test.go) |
| Public unauthenticated registration/role assignment absent | Complete | [actual route contract test](../internal/server/docs_test.go), router and registrars. This is an intentional security boundary, not a missing endpoint. |
| Tenant creation through explicit administrative CLI | Complete | [provision CLI](../cmd/provision-tenant/main.go), tenant service/repository. No public tenant creation/listing route. |
| Authorized tenant detail/update/status | Complete | [tenant handler](../internal/tenant/handler.go), service/repository and real-policy HTTP integration tests |
| Tenant-scoped user CRUD, pagination/filtering and soft deletion | Complete | [user handler](../internal/user/handler.go), service/repository, Phase 3 PostgreSQL tests |
| Multiple tenant memberships; creation/status/logical removal | Complete | User repository; 002 lifecycle fields/check and membership lifecycle/token-revocation tests |
| No global shared-identity edits by one tenant | Complete | `exclusivelyOwned` guard in user repository; shared identities return 409. This is a documented restriction, not per-tenant profile storage. |
| Duplicate email/FK/UUID/conflict handling and multi-table transactions | Complete | [access error mapping](../internal/access/access.go), access tests; concurrent create/update/attachment integration tests |
| Optimistic updates and stable bounded pagination | Complete | Tenant/user/membership timestamp checks; role profile-content digest; list tests. Role versions are not a monotonic grant-history counter. |
| Transactional change audits; best-effort login outcome audits | Complete | Access audit helper; RBAC/user/tenant repositories and audit-failure rollback tests. No complete failed-authorization/refresh/logout security-event stream. |
| Tenant-specific role CRUD and resource:action permissions | Complete | [RBAC models/catalog](../internal/rbac/models.go), [handler](../internal/rbac/handler.go), service/repository |
| Multiple roles, unioned permissions, assignment/revocation and effective-rights endpoints | Complete | RBAC policy/repository; [RBAC PostgreSQL tests](../internal/rbac/repository_integration_test.go) |
| DB-backed authorization wired into all 11 existing management routes | Complete | [application wiring](../cmd/api/main.go), existing registrars, real-policy HTTP tests for all 11 routes |
| Revalidate current active tenant/member/non-deleted actor with old JWTs | Complete | Policy and scoped transactions; inactive-account/old-JWT tests |
| 401 missing JWT, 403 insufficient authority, 404 cross-tenant targets | Complete | HTTP helpers, middleware, scope predicates and HTTP integration cases. Authorization precedes target lookup. |
| No wildcard/admin-name bypass; no unreliable permission cache | Complete | Exact supported catalog, indexed policy queries; 20 explicit bootstrap grants |
| Prevent delegation beyond current rights | Complete | Role/permission assignment containment checks; password-change/reactivation target checks; escalation tests |
| Secure opt-in initial administrator bootstrap with explicit user selection | Complete | [bootstrap transaction](../internal/rbac/bootstrap.go), CLI flags and bootstrap unit/integration tests. Initial-only; no live bootstrap in Phase 5. |
| Idempotent development-only seed, documented fixture credential | Complete | [seed CLI](../cmd/seed-dev/main.go), [wrapper](../scripts/seed-dev.sh), README. Existing credentials/status are not overwritten. Public test credential must not be used in production. |
| Unit and PostgreSQL integration coverage | Partial | Tests exist for requested behaviors, including real HTTP flows and audit rollback. Phase 5 runs unit/contract tests only; integration rerun is intentionally excluded by the no-DB-mutation requirement. |

## Phase 5 submission requirements

| Requirement | Status | Evidence / qualification |
|---|---|---|
| Every registered API route, schemas, bearer security and accurate errors | Complete | [Swagger UI](http://localhost:8080/swagger/index.html), [generated specification](swagger/swagger.yaml), [generator](../scripts/generate-swagger.sh), actual Gin route/DTO/security/permission contract tests |
| Nine-table ER diagram with real keys and tenant relationships | Complete | [ERD](erd.md), directly traced to 001/002; audit target IDs are not invented FKs. |
| Architecture, isolation, authentication, authorization, audit, concurrency/indexing/security design | Complete | [design.md](design.md), linked source and explicit tradeoffs |
| Prerequisites, Docker/env/migrations/seed/bootstrap/API/testing/documentation instructions | Complete | [README](../README.md). Setup/mutation examples are instructions, not Phase 5 executions. |
| Ignore local secrets, token/credential captures, binaries and temporary reports | Complete | [.gitignore](../.gitignore); representative rules checked in an isolated temporary Git repository. Ignore rules do not untrack existing files. |
| Inspect committed/staged diff and history for secrets | Partial | The workspace lacks usable `.git` metadata. Git commands were attempted; only a redacted worktree review and ignore-rule checks are possible here. No claim about commit history is made. |
| Original formal assignment/rubric availability | Missing | No separate artifact found. Supplied phase instructions are the only available requirements baseline. |
| Formatting, tidy, build, tests and vet | Complete | Actual command outcomes and environment flags recorded in [validation.md](validation.md). |
| Swagger generation, route/method/security/DTO validation | Complete | Pinned Swaggo generator; actual Gin registry, permission catalog/source checks, 23 DTO field-set checks, JSON/YAML equivalence and embedded-spec/UI HTTP tests; current results in validation report |
| Interactive Swagger UI with JWT Authorize and development-only default | Complete | [Registrar](../internal/server/swagger.go), [config tests](../internal/config/config_test.go), [exposure tests](../internal/server/swagger_test.go); explicit override required outside development |
| Race detector execution | Partial | Conditional on CGO/C development support. Exact probe/result is recorded in validation; unsupported is not presented as passing. |
| Preserve DB/audits/migrations during Phase 5 | Complete | No integration opt-ins, SQL/seed/bootstrap/migration/container restart or live authentication mutation executed in this phase. |

## Production controls outside implemented scope

These are documented gaps, not invented assignment features or undocumented API
endpoints. The submission is a tested local backend, not a production certificate.

| Control | Status | Current state |
|---|---|---|
| HTTPS ingress, production secret/DB-role separation and credential rotation | Missing | Local Compose credential/public seed; remote ingress and production provisioning are operator work. |
| Distributed rate limiting, MFA/lockout and email/password-recovery flows | Missing | No such middleware/endpoints exist. |
| Access JWT invalidation on logout, refresh-family replay handling, key-rotation API | Missing | Refresh credential revocation only; existing access JWT remains cryptographically valid until expiry. |
| Last-administrator protection and suspended-tenant recovery API | Missing | Initial-only bootstrap is deliberately not a repair command; operator recovery needs review. |
| Audit search/export/tamper evidence and complete security-event audit stream | Partial | Transactional change history and login audits exist, without these additional controls. |
| PostgreSQL row-level security | Missing | Application scope checks and composite FKs are implemented; direct database access is trusted. |
| Load/capacity benchmarks, deployment/backup/retention plan | Missing | No measurements or operating guarantees were fabricated. |
