# syntax=docker/dockerfile:1
#
# Single-port image: builds the frontend, embeds it into the Go binary
# (backend/web, //go:embed), and ships one binary that serves both the
# API and the SPA on MTWG_PORT. No nginx, no second container.

# ---- Stage 1: build the frontend (Framework7 + Vite PWA) -----------------
FROM node:20-alpine AS frontend-builder
WORKDIR /src
COPY frontend/package.json ./
RUN npm install --legacy-peer-deps
COPY frontend/ .
# VITE_API_BASE_URL intentionally left unset: frontend/src/js/api.js falls
# back to window.location.origin, i.e. same-origin calls to this very
# binary -- exactly what we want when everything is served from one port.
RUN npx vite build

# ---- Stage 2: build the Go binary, embedding the frontend above ----------
# backend/go.mod requires go 1.26.0 -- keep this tag in sync with that line.
FROM golang:1.26-alpine AS builder
ARG APP_VERSION=development
ARG GIT_COMMIT=N/A
ARG BUILD_TIME
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
COPY --from=frontend-builder /src/www/. ./web/dist/
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.appVersion=${APP_VERSION} -X main.gitCommit=${GIT_COMMIT} -X 'main.buildTime=${BUILD_TIME}'" \
    -o /out/mikrotik-wireguard \
    ./cmd/api

# ---- Stage 3: runtime ------------------------------------------------------
# Runs as root: /app/data is a host bind mount (see docker-compose.yaml), so
# its ownership comes from the host, not this image -- a non-root user here
# would need its UID/GID to match the host directory's, which isn't under
# this image's control. Root always has permission to create files there
# regardless of the host-side ownership.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /out/mikrotik-wireguard ./mikrotik-wireguard

ENV MTWG_PORT=8200
ENV MTWG_DB_PATH=/app/data
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8200/system/misc/health || exit 1

ENTRYPOINT ["./mikrotik-wireguard"]
