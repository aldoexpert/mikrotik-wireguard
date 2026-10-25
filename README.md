# Mikrotik WireGuard Manager

> A web panel to manage WireGuard, built for **Mikrotik RouterOS 7** management over **remote SSH** — deploy once, manage your VPN from any browser.

**Author:** Aldo · [aldo-expert.com](https://aldo-expert.com)
**Company:** [indonetsoft.com](https://indonetsoft.com)
**Stack:** Go (backend) · Framework7 PWA (frontend, embedded into the binary)
**License:** MIT

> **Current status:** the backend/frontend split is complete, every original
> WireGuard feature (clients, server, global settings, status, users,
> wake-on-lan, email/telegram) runs on the new structure, **and** the
> Mikrotik RouterOS 7 SSH integration described below is implemented and
> has been tested end-to-end against a live RouterOS 7.25 device.

---

## Table of Contents

1. [Installation (Docker)](#installation-docker)
2. [Overview & Architecture](#overview--architecture)
3. [Environment Variables](#environment-variables)
4. [Development (without Docker)](#development-without-docker)
5. [Features](#features)
6. [Roadmap](#roadmap)
7. [Mikrotik Integration](#mikrotik-integration)

---

## Installation (Docker)

### Prerequisites

- Docker ≥ 24.x
- Docker Compose v2 (`docker compose`, not the old `docker-compose`)
- One free port on the server (default `8200`) — serves **both** the UI and the API

> **No build needed.** The image is pre-built on GitHub Container Registry
> for `linux/amd64` and `linux/arm64`: `ghcr.io/aldoexpert/mikrotik-wireguard`.
> Docker automatically pulls the one matching your server's architecture.

### Installation Steps

**1. Clone the repository** *(only needed to get `docker-compose.yaml` and `.env.example`)*

```bash
git clone https://github.com/aldoexpert/mikrotik-wireguard.git
cd mikrotik-wireguard
```

**2. Create the config file**

```bash
cp .env.example .env
```

**3. Edit `.env` — fill in the required values**

```bash
nano .env
```

At minimum, set:

```env
# Generate with: openssl rand -hex 32
MTWG_JWT_SECRET=replace-with-a-long-random-string

# The address clients use to connect (your VPS/router's public IP)
MTWG_ENDPOINT_ADDRESS=203.0.113.10
```

> Generate a secret with: `openssl rand -hex 32`

**4. Run it**

```bash
docker compose pull
docker compose up -d
```

Docker pulls `ghcr.io/aldoexpert/mikrotik-wireguard:latest` — no local build.

**5. Open the app**

```
http://<SERVER-IP>:8200
```

Log in with:
- **Username:** `admin`
- **Password:** `admin`

> **Change the password immediately** after your first login, on the Profile page.

---

### Update / Upgrade

Since the image is pre-built on the registry, upgrading is just a pull + restart:

```bash
docker compose pull
docker compose up -d
```

> **Don't run `docker compose down -v`** — the `-v` flag deletes the volume
> and all your data (clients, keys, settings).

Persistent data lives on the host in `./data` (bind mount, see `docker-compose.yaml`), so it survives image upgrades untouched.

---

### Build from Source (Developer)

If you want to build the image yourself (e.g. after modifying the code):

```bash
docker compose build --no-cache
docker compose up -d
```

To build multi-arch and push to your own registry:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<your-username>/mikrotik-wireguard:latest --push .
```

---

### Port Used

| Port | Purpose |
|---|---|
| `8200` | UI + API, single port (set via `APP_PORT` in `.env`) |
| `51820/udp` | The WireGuard tunnel itself, on whichever host actually runs `wg0` (not this container, unless you still rely on a local interface — see the commented `network_mode: host` block in `docker-compose.yaml`) |

---

### Troubleshooting

**View logs:**
```bash
docker compose logs -f app
```

**Restart:**
```bash
docker compose restart app
```

**Container status:**
```bash
docker compose ps
```

**Forgot the admin password:**

There's no `reset-password` CLI yet. The initial admin user is only
auto-seeded while `./data/users/` is empty, so to get back in:

```bash
docker compose stop app
rm -rf ./data/users
# optionally set MTWG_USERNAME / MTWG_PASSWORD in .env first
docker compose up -d
```

A fresh admin user is re-seeded from `MTWG_USERNAME` / `MTWG_PASSWORD`
(default `admin` / `admin`) on the next start. This only touches the
`users/` data — clients, server keys and settings are untouched.

---

## Overview & Architecture

```
mikrotik-wireguard/
├── backend/                 # Go REST API + embedded frontend
│   ├── cmd/api/             # entry point
│   ├── web/                 # //go:embed of the built frontend (web/dist/)
│   └── internal/
│       ├── core/            # module/controller/method router + JSON response
│       ├── config/          # flags + env vars (MTWG_*)
│       ├── middleware/      # auth (JWT), CORS, logging, recovery
│       ├── library/         # store (jsondb), wireguard, mikrotik (SSH), network, emailer, telegram, jwt
│       ├── model/           # data structs (client, server, user, settings, ...)
│       └── modules/         # auth, users, wireguard, network, system
├── frontend/                 # Framework7 PWA (SPA, consumes the backend REST API)
│   └── src/
│       ├── app.f7           # shell (panel menu + main view)
│       ├── js/               # app.js, routes.js, store.js, api.js
│       └── pages/            # login, clients, server, settings, users, ...
├── data/                    # persistent data (users, clients, settings) -- JSON files, gitignored
├── Dockerfile                # multi-stage: builds the frontend, embeds it into the Go binary
└── docker-compose.yaml       # single service, single port, ready to run
```

The backend is a **pure REST API** (it renders no HTML) -- every endpoint
follows the `/{module}/{controller}/{method}/{param?}` pattern and replies
with a consistent JSON envelope:

```json
{ "status": true, "code": 200, "message": "", "data": {}, "datas": [] }
```

Auth uses a **JWT Bearer token** (not a cookie session). The frontend is a
static Framework7 PWA that is built and embedded straight into the Go
binary (see `Dockerfile` and `backend/web/embed.go`), so in production both
the API and the UI are served from the same origin/port -- no CORS/CSRF
concerns there either. There's no granular RBAC -- just an `admin` flag per
user, matching wireguard-ui's original design.

Data is stored as JSON files under `data/` on the host (no MySQL/Postgres),
so deployment stays lightweight for a single container.

---

## Environment Variables

Every variable uses the `MTWG_` prefix. The full list is in
[`.env.example`](.env.example). The important ones:

| Variable | Default | Description |
|---|---|---|
| `MTWG_JWT_SECRET` | *(required)* | The JWT session signing key. Change it for every production deploy. |
| `MTWG_DISABLE_LOGIN` | `false` | Disables authentication. **Never use this in production.** |
| `MTWG_CORS_ALLOWED_ORIGINS` | `*` | Allowed CORS origin(s). Not needed for the normal single-port setup (same-origin); only set this if you call the API from a different origin. |
| `MTWG_USERNAME` / `MTWG_PASSWORD` | `admin` / `admin` | Initial admin user, only used while the database is still empty. |
| `MTWG_SERVER_INTERFACE_ADDRESSES` | `10.252.1.1/24` | The WireGuard VPN subnet. The server itself owns `.1`; client IPs (auto-suggested or manual) start from `.2` -- `.1`, the network address (`.0`) and the broadcast address (`.255`) are always excluded. |
| `MTWG_SERVER_LISTEN_PORT` | `51820` | The WireGuard UDP port. |
| `MTWG_ENDPOINT_ADDRESS` | *(auto-detected public IP)* | The address clients use to connect. |
| `MTWG_SUBNET_RANGES` | *(empty)* | Extra IP pools, format `name1:cidr1,cidr2;name2:cidr3`. |
| `MTWG_CONFIG_FILE_PATH` | `/app/data/wg0.conf` (Docker) | Where the locally-written `wg0.conf` is saved. Defaults into the persisted data volume, since the image has no `/etc/wireguard` (no `wireguard-tools`, no local wg0 device -- this project targets Mikrotik RouterOS 7 over SSH). |
| `MTWG_SMTP_*`, `MTWG_SENDGRID_API_KEY` | *(empty)* | Send client configs by email. |
| `MTWG_TELEGRAM_TOKEN` | *(empty)* | Send client configs via a Telegram bot. |
| `APP_PORT` | `8200` | Host port published by `docker-compose.yaml` (container always listens on `8200` internally). |

---

## Development (without Docker)

### Backend

```bash
cd backend
go run ./cmd/api
# or with env overrides:
MTWG_DISABLE_LOGIN=true MTWG_CONFIG_FILE_PATH=/tmp/wg0.conf go run ./cmd/api
```

### Frontend

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev          # dev server on :5173, proxies API calls to :8200 (see vite.config.js)
npm run build         # production build into frontend/www/
```

This two-process setup (`:5173` + `:8200`) is for local development only. In
production (Docker), `npm run build`'s output is copied into
`backend/web/dist/` and embedded into the Go binary at compile time (see
`Dockerfile` and `backend/web/embed.go`), so the shipped app is a single
binary serving everything on one port -- no separate frontend
container/process.

To test that single-binary setup locally without Docker:

```bash
cd backend && make build-frontend   # builds ../frontend and syncs into web/dist/
go run ./cmd/api                    # now serving UI + API on :8200
```

---

## Features

- WireGuard client management: create/edit/delete, enable/disable, automatic
  IP suggestion, QR code, `.conf` download, send via email/Telegram
- WireGuard server configuration: interface address/port, key pair, apply
  config
- Global settings: DNS, MTU, persistent keepalive, firewall mark, etc.
- Multi-user (admin & manager) without granular RBAC
- Real-time peer connection status (handshake, traffic) -- from the local
  WireGuard device, or from a Mikrotik router when that integration is enabled
- **Mikrotik RouterOS 7 integration over SSH**: push the server interface
  and client peers to a real router instead of (or alongside) the local
  `wg0.conf` -- see [Mikrotik Integration](#mikrotik-integration) below
- Wake-on-LAN for hosts on the same LAN
- Installable PWA (Framework7) -- can be installed as an app on desktop/mobile

---

## Roadmap

- [ ] Multi-router Mikrotik support per instance (today: one router per app instance)
- [ ] Pin the Mikrotik SSH host key fingerprint instead of trusting it on
      first connect (see [Mikrotik Integration](#mikrotik-integration) below)
- [ ] `reset-password` CLI (today: manual, see [Troubleshooting](#troubleshooting))

---

## Mikrotik Integration

When enabled, clicking **Apply Configuration** on the Server page pushes the
WireGuard interface and every enabled client (as a peer) to a Mikrotik
RouterOS 7 device over SSH, in addition to writing the local `wg0.conf`. The
Status page also switches to reading live handshake/traffic data from the
router instead of the local kernel WireGuard device.

- Every peer this app manages is tagged with a RouterOS comment
  (`mtwg:<client-id>`), so re-applying is idempotent and it never touches a
  peer it didn't create.
- Disabling or deleting a client removes its peer from the router on the
  next Apply; re-enabling it recreates the peer.
- The server's own `/ip address` (e.g. `10.252.1.1/24`) is also synced onto
  the WireGuard interface -- without it the router has no routable address
  inside the tunnel subnet, so peers could handshake but traffic to the
  server itself would have nowhere to go.
- Authentication is **always by SSH key**, never password.

### One-time setup on the router

Create a dedicated, least-privilege user instead of using the router's
admin account for this integration:

```
# on the router (e.g. via Winbox terminal), create a restricted group:
/user group add name=wg-automation policy=ssh,read,write,test,!local,!telnet,!ftp,!reboot,!policy,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api

# create the user in that group (set any throwaway password; it won't be used):
/user add name=wgmanager group=wg-automation

# generate a keypair on the machine running this app and import the public half:
#   ssh-keygen -t ed25519 -f ./wgmanager -N "" -C "mikrotik-wireguard-app"
#   scp -P <ssh-port> ./wgmanager.pub <user>@<router>:wgmanager.pub
/user/ssh-keys/import public-key-file=wgmanager.pub user=wgmanager
```

This keeps the integration's access scoped to SSH + read/write/test only --
it cannot reboot the router, manage other users, or use Winbox/API/FTP/Telnet.

### App-side configuration

In the panel, go to **WireGuard → Mikrotik Integration** (admin only) and
fill in:

| Field | Example |
|---|---|
| Host / IP Address | `203.0.113.10` (example -- use your router's actual address) |
| SSH Port | `22` (or a custom port, e.g. `8222`, if that's what the router's SSH service listens on) |
| Username | `wgmanager` |
| WireGuard Interface Name | `wireguard1` (created automatically if it doesn't exist) |
| SSH Private Key | the **private** half of the keypair generated above |

Use **Test Connection** to verify before saving, then toggle **Enabled** and
save. The next "Apply Configuration" on the Server page syncs to the router.
