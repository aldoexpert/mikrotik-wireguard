# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder

ARG APP_VERSION=development
ARG GIT_COMMIT=N/A
ARG BUILD_TIME

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.appVersion=${APP_VERSION} -X main.gitCommit=${GIT_COMMIT} -X 'main.buildTime=${BUILD_TIME}'" \
    -o /out/mikrotik-wireguard-backend \
    ./cmd/api

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /out/mikrotik-wireguard-backend ./mikrotik-wireguard-backend

RUN mkdir -p /app/db && chown -R app:app /app
USER app

ENV MTWG_PORT=8080
ENV MTWG_DB_PATH=/app/db
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/system/misc/health || exit 1

ENTRYPOINT ["./mikrotik-wireguard-backend"]
