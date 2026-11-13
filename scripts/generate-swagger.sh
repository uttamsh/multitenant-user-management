#!/usr/bin/env sh
# Pinned generator; generated Go embeds the spec so runtime needs no source files.
set -eu
cd "$(dirname "$0")/.."
exec go tool swag init \
  --generalInfo main.go \
  --dir cmd/api,internal/auth,internal/tenant,internal/user,internal/rbac,internal/server,internal/httpapi,internal/middleware \
  --parseInternal \
  --output docs/swagger --packageName swagger --outputTypes go,json,yaml
