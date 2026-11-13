# Database ER diagram

Source of truth: [001_init.sql](../migrations/001_init.sql) and
[002_membership_lifecycle.sql](../migrations/002_membership_lifecycle.sql).
There are **nine tables**. The diagram shows actual foreign keys; HTTP target IDs
and audit `target_id` values do not introduce additional database foreign keys.

```mermaid
erDiagram
    tenants ||--o{ tenant_users : "tenant_id"
    users ||--o{ tenant_users : "user_id"
    tenants ||--o{ roles : "tenant_id"
    roles ||--o{ role_permissions : "tenant_id + role_id"
    permissions ||--o{ role_permissions : "permission_id"
    tenant_users ||--o{ user_roles : "tenant_id + user_id"
    roles ||--o{ user_roles : "tenant_id + role_id"
    tenant_users ||--o{ refresh_tokens : "tenant_id + user_id"
    tenants o|--o{ audit_logs : "nullable tenant_id"
    users o|--o{ audit_logs : "nullable actor_id"

    tenants {
        UUID id PK
        VARCHAR_200 name
        VARCHAR_50 code UK
        VARCHAR_20 status "active or suspended"
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }
    users {
        UUID id PK
        VARCHAR_255 email "unique LOWER(email) index"
        TEXT password_hash "bcrypt; never returned"
        VARCHAR_200 full_name
        TIMESTAMPTZ deleted_at "nullable soft deletion"
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }
    tenant_users {
        UUID tenant_id PK, FK
        UUID user_id PK, FK
        VARCHAR_20 status "active or suspended"
        TIMESTAMPTZ joined_at
        TIMESTAMPTZ removed_at "nullable; migration 002"
        TIMESTAMPTZ updated_at "migration 002"
    }
    roles {
        UUID id PK
        UUID tenant_id FK
        VARCHAR_100 name "unique within tenant"
        TEXT description "nullable"
        TIMESTAMPTZ created_at
    }
    permissions {
        UUID id PK
        VARCHAR_100 resource "composite unique resource + action"
        VARCHAR_100 action "composite unique resource + action"
    }
    role_permissions {
        UUID tenant_id FK
        UUID role_id PK, FK
        UUID permission_id PK, FK
    }
    user_roles {
        UUID tenant_id PK, FK
        UUID user_id PK, FK
        UUID role_id PK, FK
    }
    refresh_tokens {
        UUID id PK
        UUID tenant_id FK
        UUID user_id FK
        TEXT token_hash UK "SHA-256 digest, not bearer token"
        TIMESTAMPTZ expires_at
        TIMESTAMPTZ revoked_at "nullable"
        TIMESTAMPTZ created_at
    }
    audit_logs {
        BIGSERIAL id PK
        UUID tenant_id FK "nullable"
        UUID actor_id FK "nullable; operator/anonymous events"
        VARCHAR_100 action
        VARCHAR_100 target_type "nullable"
        UUID target_id "nullable; intentionally no FK"
        JSONB metadata "default empty object"
        TIMESTAMPTZ created_at
    }
```

## Keys and invariants

| Table | Primary key | Additional uniqueness / references |
|---|---|---|
| `tenants` | `id` | Unique `code` |
| `users` | `id` | Unique expression index `LOWER(email)`, including deleted users |
| `tenant_users` | `(tenant_id, user_id)` | Separate FKs to `tenants.id`, `users.id` |
| `roles` | `id` | Unique `(tenant_id, name)` and `(tenant_id, id)`; tenant FK |
| `permissions` | `id` | Unique `(resource, action)`; shared identifiers, not shared authority |
| `role_permissions` | `(role_id, permission_id)` | Composite FK `(tenant_id, role_id)` → `roles`; permission FK |
| `user_roles` | `(tenant_id, user_id, role_id)` | Composite FKs to membership and tenant role |
| `refresh_tokens` | `id` | Unique `token_hash`; composite membership FK |
| `audit_logs` | `id` | Nullable tenant/user FKs; targets remain referencable in history after role deletion |

The composite role FKs prevent granting a role from another tenant. Membership FKs
prevent refresh credentials and assignments without a membership row. They do not
enforce account activity or user soft-deletion: services/repositories must check
those conditions. `removed_at IS NULL OR status = 'suspended'` is the added 002
check constraint. Membership removal retains rows, satisfying historical FKs.

Users are global identities; many memberships are possible. Tenant-local CRUD
refuses global profile/password edits or global soft-deletion when another
non-removed membership exists, including a suspended membership. Removing one
membership never deletes another tenant's relationship.

There are no soft-deletion columns on roles, no `updated_at` column on roles, no
refresh-token family/replacement column, and no global administrator table.
Role optimistic versions are computed from profile content, not persisted columns.

## Indexes in the migrations

In addition to PK/unique indexes, 001 creates membership lookup by `user_id`,
refresh lookup by `(tenant_id, user_id)`, audit lookup by
`(tenant_id, created_at DESC)`, and user-role lookup by `(tenant_id, user_id)`.
The last index overlaps the leading columns of the `user_roles` PK; it is retained
unchanged. Migration 002 adds only the lifecycle columns/check; no index is added.
There is no trigram/full-text index for substring user search. No migration has
been changed by documentation work.
