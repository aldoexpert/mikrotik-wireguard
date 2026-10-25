# Backend -- Mikrotik WireGuard Manager

Go REST API. See the root [README.md](../README.md) for the full
architecture overview (backend + frontend + docker).

## Running

```bash
go run ./cmd/api
# or
make run
```

See `../.env.example` for the full list of environment variables (`MTWG_*`).

## Structure

```
cmd/api/main.go           entry point: load config, init db, register modules, start server
internal/core/             module/controller/method router + standard JSON response
internal/config/           flags + env vars
internal/middleware/       auth (JWT), CORS, logging, recovery
internal/library/          store (jsondb), wireguard, mikrotik (SSH), network, emailer, telegram, jwt, hash
internal/model/            data structs
internal/modules/          business logic per domain (auth, users, wireguard, network, system)
```

## Adding a New Module

1. Create a folder at `internal/modules/{name}/`.
2. Create `{controller}_controller.go` with an `XController` struct + methods
   shaped as `func (c *XController) MethodName(w http.ResponseWriter, r *http.Request, params []string)`.
3. Create `module.go` with `Register(registry *core.Registry, cfg *config.App, db store.IStore)`
   that registers the controller via `registry.RegisterController` and each
   endpoint via `registry.RegisterMethod("module", "controller", "method", handler)`.
4. Call `{name}.Register(app.Registry, cfg, db)` from `cmd/api/main.go`.

Use `middleware.RequireAuth(cfg)` for endpoints that need a login, and wrap
it again with `middleware.RequireAdmin` for admin-only endpoints.

## Response Helpers

```go
core.Success(w, "message", data)         // {status:true, code:200, data:{...}}
core.SuccessList(w, "message", datas)    // {status:true, code:200, datas:[...]}
core.BadRequest(w, "message")            // 400
core.Unauthorized(w, "message")          // 401
core.Forbidden(w, "message")             // 403
core.NotFound(w, "message")              // 404
core.InternalError(w, "message", err)    // 500, err is logged server-side
```

## Mikrotik RouterOS 7 integration

`internal/library/mikrotik` talks to a RouterOS 7 device over SSH (key auth
only). `internal/modules/wireguard/server_controller.go` (`ApplyConfig`)
always writes the local `wg0.conf`, and additionally calls
`mikrotik.ApplySync` when `MikrotikSettings.Enabled` is true;
`status_controller.go` (`Get`) likewise switches between the local `wgctrl`
device and `mikrotik.GetPeerStatuses` based on that same flag. Settings are
managed via `internal/modules/wireguard/mikrotik_settings_controller.go`
(`GET/POST /wireguard/mikrotik/{get,update,test}`). See the root
[README.md](../README.md#mikrotik-integration) for the operator-facing setup
steps (creating a restricted RouterOS user, generating the SSH key).

Idempotency: every peer this app creates is tagged with a RouterOS comment
`mtwg:<client-id>` (see `peerTag` in `mikrotik.go`). `ApplySync` finds/updates
peers by that comment and never touches a peer whose comment doesn't start
with `mtwg:`, so it's safe to run on an interface the operator also manages
by hand.
