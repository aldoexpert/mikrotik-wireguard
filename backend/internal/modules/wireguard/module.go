// Package wireguard manages the local WireGuard server configuration and
// its clients (peers).
//
// ApplyConfig always writes the local wg0.conf (wgctrl reads that file for
// the Status page too). When Mikrotik settings are Enabled, ApplyConfig
// additionally pushes the same server/peer config to the RouterOS 7
// device over SSH -- see internal/library/mikrotik and
// mikrotik_settings_controller.go.
package wireguard

import (
	"log"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/emailer"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

// Register wires the "wireguard" module's endpoints into registry.
//
//	GET  /wireguard/clients/list?interface_id=<id>
//	GET  /wireguard/clients/get/<id>
//	POST /wireguard/clients/create
//	POST /wireguard/clients/update
//	POST /wireguard/clients/delete
//	POST /wireguard/clients/setstatus
//	GET  /wireguard/clients/download/<id>
//	POST /wireguard/clients/email
//	POST /wireguard/clients/telegram
//	GET  /wireguard/clients/suggestips?interface_id=<id>
//
//	GET  /wireguard/interfaces/list                (admin)
//	GET  /wireguard/interfaces/get/<id>            (admin)
//	POST /wireguard/interfaces/create              (admin)
//	POST /wireguard/interfaces/update              (admin)
//	POST /wireguard/interfaces/delete              (admin)
//	POST /wireguard/interfaces/updatekeypair       (admin)
//	POST /wireguard/interfaces/applyconfig         (admin)
//	POST /wireguard/interfaces/applyall            (admin)
//
//	GET  /wireguard/mikrotik/get                  (admin)
//	POST /wireguard/mikrotik/update               (admin)
//	POST /wireguard/mikrotik/test                 (admin)
//
//	GET  /wireguard/status/get
func Register(registry *core.Registry, cfg *config.App, db store.IStore, mailer emailer.Emailer) {
	requireAuth := middleware.RequireAuth(cfg)

	clients := NewClientsController(cfg, db, mailer)
	registry.RegisterController("wireguard", "clients", clients)
	registry.RegisterMethod("wireguard", "clients", "list", requireAuth(clients.List))
	registry.RegisterMethod("wireguard", "clients", "get", requireAuth(clients.Get))
	registry.RegisterMethod("wireguard", "clients", "create", requireAuth(clients.Create))
	registry.RegisterMethod("wireguard", "clients", "update", requireAuth(clients.Update))
	registry.RegisterMethod("wireguard", "clients", "delete", requireAuth(clients.Delete))
	registry.RegisterMethod("wireguard", "clients", "setstatus", requireAuth(clients.SetStatus))
	registry.RegisterMethod("wireguard", "clients", "download", requireAuth(clients.Download))
	registry.RegisterMethod("wireguard", "clients", "email", requireAuth(clients.Email))
	registry.RegisterMethod("wireguard", "clients", "telegram", requireAuth(clients.Telegram))
	registry.RegisterMethod("wireguard", "clients", "suggestips", requireAuth(clients.SuggestIPs))
	registry.RegisterMethod("wireguard", "clients", "defaults", requireAuth(clients.Defaults))

	interfaces := NewInterfacesController(db, cfg.WgConfTemplate)
	registry.RegisterController("wireguard", "interfaces", interfaces)
	registry.RegisterMethod("wireguard", "interfaces", "list", requireAuth(middleware.RequireAdmin(interfaces.List)))
	registry.RegisterMethod("wireguard", "interfaces", "get", requireAuth(middleware.RequireAdmin(interfaces.Get)))
	registry.RegisterMethod("wireguard", "interfaces", "create", requireAuth(middleware.RequireAdmin(interfaces.Create)))
	registry.RegisterMethod("wireguard", "interfaces", "update", requireAuth(middleware.RequireAdmin(interfaces.Update)))
	registry.RegisterMethod("wireguard", "interfaces", "delete", requireAuth(middleware.RequireAdmin(interfaces.Delete)))
	registry.RegisterMethod("wireguard", "interfaces", "updatekeypair", requireAuth(middleware.RequireAdmin(interfaces.UpdateKeyPair)))
	registry.RegisterMethod("wireguard", "interfaces", "applyconfig", requireAuth(middleware.RequireAdmin(interfaces.ApplyConfig)))
	registry.RegisterMethod("wireguard", "interfaces", "applyall", requireAuth(middleware.RequireAdmin(interfaces.ApplyAll)))

	mikrotikSettings := NewMikrotikSettingsController(db)
	registry.RegisterController("wireguard", "mikrotik", mikrotikSettings)
	registry.RegisterMethod("wireguard", "mikrotik", "get", requireAuth(middleware.RequireAdmin(mikrotikSettings.Get)))
	registry.RegisterMethod("wireguard", "mikrotik", "update", requireAuth(middleware.RequireAdmin(mikrotikSettings.Update)))
	registry.RegisterMethod("wireguard", "mikrotik", "test", requireAuth(middleware.RequireAdmin(mikrotikSettings.Test)))

	status := NewStatusController(db)
	registry.RegisterController("wireguard", "status", status)
	registry.RegisterMethod("wireguard", "status", "get", requireAuth(status.Get))

	registerMenus(registry)
	log.Println("[MODULE] wireguard registered")
}

// Link values below are frontend page routes (see frontend/src/js/routes.js),
// not backend API paths -- the frontend panel renders this menu directly.
func registerMenus(registry *core.Registry) {
	registry.RegisterMenu(core.MenuGroup{
		Header: "WireGuard",
		Icon:   "shield",
		List: []core.MenuItem{
			{Link: "/", Label: "Clients"},
			{Link: "/status/", Label: "Status"},
			{Link: "/interfaces/", Label: "Interfaces", Admin: true},
			{Link: "/mikrotik/", Label: "Mikrotik Integration", Admin: true},
		},
	})
}
