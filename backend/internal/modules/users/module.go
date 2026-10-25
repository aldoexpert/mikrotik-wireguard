// Package users manages application accounts (admin/manager), kept as a
// simple flat list -- no RBAC, matching upstream wireguard-ui's model.
package users

import (
	"log"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

// Register wires the "users" module's endpoints into registry.
//
//	GET  /users/account/list              (admin)
//	GET  /users/account/get/<username>     (self or admin)
//	POST /users/account/create             (admin)
//	POST /users/account/update             (self or admin)
//	POST /users/account/delete             (admin)
func Register(registry *core.Registry, cfg *config.App, db store.IStore) {
	controller := NewAccountController(cfg, db)
	registry.RegisterController("users", "account", controller)

	requireAuth := middleware.RequireAuth(cfg)

	registry.RegisterMethod("users", "account", "list", requireAuth(middleware.RequireAdmin(controller.List)))
	registry.RegisterMethod("users", "account", "get", requireAuth(controller.Get))
	registry.RegisterMethod("users", "account", "create", requireAuth(middleware.RequireAdmin(controller.Create)))
	registry.RegisterMethod("users", "account", "update", requireAuth(controller.Update))
	registry.RegisterMethod("users", "account", "delete", requireAuth(middleware.RequireAdmin(controller.Delete)))

	registerMenus(registry)
	log.Println("[MODULE] users registered")
}

func registerMenus(registry *core.Registry) {
	registry.RegisterMenu(core.MenuGroup{
		Header: "Administration",
		Icon:   "person_2_fill",
		List: []core.MenuItem{
			{Link: "/users/", Label: "Users", Admin: true},
		},
	})
}
