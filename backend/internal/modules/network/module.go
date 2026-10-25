// Package network manages local LAN utilities unrelated to WireGuard
// itself -- today just Wake-on-LAN host bookmarks.
package network

import (
	"log"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

// Register wires the "network" module's endpoints into registry.
//
//	GET    /network/wol/list
//	POST   /network/wol/save
//	POST   /network/wol/delete
//	POST   /network/wol/wake
func Register(registry *core.Registry, cfg *config.App, db store.IStore) {
	wol := NewWolController(db)
	registry.RegisterController("network", "wol", wol)

	requireAuth := middleware.RequireAuth(cfg)
	registry.RegisterMethod("network", "wol", "list", requireAuth(wol.List))
	registry.RegisterMethod("network", "wol", "save", requireAuth(wol.Save))
	registry.RegisterMethod("network", "wol", "delete", requireAuth(wol.Delete))
	registry.RegisterMethod("network", "wol", "wake", requireAuth(wol.Wake))

	registerMenus(registry)
	log.Println("[MODULE] network registered")
}

func registerMenus(registry *core.Registry) {
	registry.RegisterMenu(core.MenuGroup{
		Header: "Network",
		Icon:   "wifi",
		List: []core.MenuItem{
			{Link: "/wol/", Label: "Wake on LAN"},
		},
	})
}
