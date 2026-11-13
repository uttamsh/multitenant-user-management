-- Apply once after 001 and 002. No application records or audit history removed.
-- Triggers keep every writer (including bootstrap) in the invalidation protocol.
BEGIN;

ALTER TABLE tenants
    ADD COLUMN authorization_revision BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT tenants_authorization_revision_nonnegative
        CHECK (authorization_revision >= 0);

CREATE FUNCTION bump_tenant_authorization_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        UPDATE tenants SET authorization_revision = authorization_revision + 1
        WHERE id = OLD.tenant_id;
    END IF;
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        UPDATE tenants SET authorization_revision = authorization_revision + 1
        WHERE id = NEW.tenant_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER roles_authorization_revision AFTER INSERT OR UPDATE OR DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION bump_tenant_authorization_revision();
CREATE TRIGGER role_permissions_authorization_revision AFTER INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION bump_tenant_authorization_revision();
CREATE TRIGGER user_roles_authorization_revision AFTER INSERT OR UPDATE OR DELETE ON user_roles
FOR EACH ROW EXECUTE FUNCTION bump_tenant_authorization_revision();
CREATE TRIGGER tenant_users_authorization_revision AFTER INSERT OR UPDATE OR DELETE ON tenant_users
FOR EACH ROW EXECUTE FUNCTION bump_tenant_authorization_revision();

CREATE FUNCTION tenant_status_authorization_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.authorization_revision := OLD.authorization_revision + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenants_status_authorization_revision BEFORE UPDATE OF status ON tenants
FOR EACH ROW EXECUTE FUNCTION tenant_status_authorization_revision();

-- Global identities and permission identifiers can affect several tenants.
-- Stable tenant lock order reduces deadlock risk for administrative SQL changes.
CREATE FUNCTION user_state_authorization_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE affected UUID;
BEGIN
    IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        FOR affected IN SELECT tenant_id FROM tenant_users WHERE user_id = NEW.id ORDER BY tenant_id LOOP
            UPDATE tenants SET authorization_revision = authorization_revision + 1 WHERE id = affected;
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER users_state_authorization_revision AFTER UPDATE OF deleted_at ON users
FOR EACH ROW EXECUTE FUNCTION user_state_authorization_revision();

CREATE FUNCTION permission_identity_authorization_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE affected UUID;
BEGIN
    IF NEW.resource IS DISTINCT FROM OLD.resource OR NEW.action IS DISTINCT FROM OLD.action THEN
        FOR affected IN SELECT DISTINCT tenant_id FROM role_permissions WHERE permission_id = NEW.id ORDER BY tenant_id LOOP
            UPDATE tenants SET authorization_revision = authorization_revision + 1 WHERE id = affected;
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER permissions_identity_authorization_revision AFTER UPDATE OF resource, action ON permissions
FOR EACH ROW EXECUTE FUNCTION permission_identity_authorization_revision();

COMMIT;
