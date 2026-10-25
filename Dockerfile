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
FROM golang:1.22-alpine AS builder
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
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /out/mikrotik-wireguard ./mikrotik-wireguard

RUN mkdir -p /app/db && chown -R app:app /app
USER app

ENV MTWG_PORT=8200
ENV MTWG_DB_PATH=/app/db
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8200/system/misc/health || exit 1

ENTRYPOINT ["./mikrotik-wireguard"]
