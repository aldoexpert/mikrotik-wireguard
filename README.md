# Mikrotik WireGuard Manager

**Author:** Aldo · [aldo-expert.com](https://aldo-expert.com)
**Company:** [indonetsoft.com](https://indonetsoft.com)
**Stack:** Go (backend) · Framework7 PWA (frontend)
**License:** MIT

A web panel to manage WireGuard, built for **Mikrotik RouterOS 7** management
over **remote SSH** — deploy once, manage your VPN from any browser.

> **Current status:** the backend/frontend split is complete, every original
> WireGuard feature (clients, server, global settings, status, users,
> wake-on-lan, email/telegram) runs on the new structure, **and** the
> Mikrotik RouterOS 7 SSH integration described below is implemented and
> has been tested end-to-end against a live RouterOS 7.24 device.

---

## Architecture

```
mikrotik-wireguard/
├── backend/                 # Go REST API (no UI here)
│   ├── cmd/api/             # entry point
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
└── docker-compose.yaml       # backend + frontend, ready to run
```

The backend is a **pure REST API** (it renders no HTML) -- every endpoint
follows the `/{module}/{controller}/{method}/{param?}` pattern and replies
with a consistent JSON envelope:

```json
{ "status": true, "code": 200, "message": "", "data": {}, "datas": [] }
```

Auth uses a **JWT Bearer token** (not a cookie session), so the frontend --
running on a different origin/port -- can call the backend freely without
CSRF/cross-site cookie issues. There's no granular RBAC -- just an `admin`
flag per user, matching wireguard-ui's original design.

Data is stored as JSON files under `data/` on the host (no MySQL/Postgres),
so deployment stays lightweight for a single container.

---

## Quick Start (Docker Compose)

```bash
cp .env.example .env
# edit .env: at minimum set MTWG_JWT_SECRET and MTWG_ENDPOINT_ADDRESS

docker compose up -d --build
```

- Frontend: http://localhost:8081 (default login `admin` / `admin`,
  **change it** on the Profile page right after your first login)
- Backend API: http://localhost:8080

Persistent data is stored in `./data` on the host (see `docker-compose.yaml`).

> `VITE_API_BASE_URL` is baked into the frontend build when the image is
> built. If the backend's address changes, rebuild the frontend image:
> `docker compose build frontend`.

---

## Environment Variables (backend)

Every variable uses the `MTWG_` prefix. The full list is in
[`.env.example`](.env.example). The important ones:

| Variable | Default | Description |
|---|---|---|
| `MTWG_JWT_SECRET` | *(required)* | The JWT session signing key. Change it for every production deploy. |
| `MTWG_DISABLE_LOGIN` | `false` | Disables authentication. **Never use this in production.** |
| `MTWG_CORS_ALLOWED_ORIGINS` | `*` | Frontend origins allowed to call the API. |
| `MTWG_USERNAME` / `MTWG_PASSWORD` | `admin` / `admin` | Initial admin user, only used while the database is still empty. |
| `MTWG_SERVER_INTERFACE_ADDRESSES` | `10.252.1.1/24` | The WireGuard VPN subnet. The server itself owns `.1`; client IPs (auto-suggested or manual) start from `.2` -- `.1`, the network address (`.0`) and the broadcast address (`.255`) are always excluded. |
| `MTWG_SERVER_LISTEN_PORT` | `51820` | The WireGuard UDP port. |
| `MTWG_ENDPOINT_ADDRESS` | *(auto-detected public IP)* | The address clients use to connect. |
| `MTWG_SUBNET_RANGES` | *(empty)* | Extra IP pools, format `name1:cidr1,cidr2;name2:cidr3`. |
| `MTWG_SMTP_*`, `MTWG_SENDGRID_API_KEY` | *(empty)* | Send client configs by email. |
| `MTWG_TELEGRAM_TOKEN` | *(empty)* | Send client configs via a Telegram bot. |

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
npm run dev          # dev server on :5173, talks to the backend via VITE_API_BASE_URL
npm run build         # production build into frontend/www/
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
  `wg0.conf` -- see "Mikrotik integration" below
- Wake-on-LAN for hosts on the same LAN
- Installable PWA (Framework7) -- can be installed as an app on desktop/mobile

## Roadmap

- [ ] Multi-router Mikrotik support per instance (today: one router per app instance)
- [ ] Pin the Mikrotik SSH host key fingerprint instead of trusting it on
      first connect (see "Mikrotik integration" below)

---

## Mikrotik integration

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
| Host / IP Address | `203.0.113.10` |
| SSH Port | `22` (or a custom port, e.g. `8222`, if that's what the router's SSH service listens on) |
| Username | `wgmanager` |
| WireGuard Interface Name | `wireguard1` (created automatically if it doesn't exist) |
| SSH Private Key | the **private** half of the keypair generated above |

Use **Test Connection** to verify before saving, then toggle **Enabled** and
save. The next "Apply Configuration" on the Server page syncs to the router.

