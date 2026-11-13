# syntax=docker/dockerfile:1
# go.mod requires Go 1.26; use the maintained patch release of that minor line.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY docs/swagger ./docs/swagger
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/api ./cmd/api && \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

FROM scratch AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/api /app/api
COPY --from=build --chown=65532:65532 /out/healthcheck /app/healthcheck
WORKDIR /app
USER 65532:65532
ENV APP_ENV=production HTTP_ADDR=0.0.0.0:8080
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=4s --start-period=15s --retries=3 CMD ["/app/healthcheck"]
ENTRYPOINT ["/app/api"]
