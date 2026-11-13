-- Additive lifecycle fields preserve membership, refresh-token and role history.
-- Apply explicitly after 001_init.sql; the API never runs migrations itself.
BEGIN;
ALTER TABLE tenant_users
    ADD COLUMN removed_at TIMESTAMPTZ,
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD CONSTRAINT tenant_users_removed_status
        CHECK (removed_at IS NULL OR status = 'suspended');
COMMIT;
