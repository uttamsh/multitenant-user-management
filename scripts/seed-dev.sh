#!/usr/bin/env sh
# Explicit development opt-in is forwarded to the seed command.
set -eu
cd "$(dirname "$0")/.."
exec go run ./cmd/seed-dev "$@"
