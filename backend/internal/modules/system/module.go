// Package system exposes small, auth-free or lightly-authenticated
// endpoints: health check, version info, host network info and the
// dirty-config check used to prompt an admin to "apply" pending changes.
package system

import (
	"log"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

// Register wires the "system" module's endpoints into registry.
//
//	GET /system/misc/health          (public)
//	GET /system/misc/about           (public)
//	GET /system/misc/machineips      (authenticated)
//	GET /system/misc/subnetranges    (authenticated)
//	GET /system/misc/haseschanged    (authenticated)
func Register(registry *core.Registry, cfg *config.App, db store.IStore) {
	controller := NewMiscController(cfg, db)
	registry.RegisterController("system", "misc", controller)

	requireAuth := middleware.RequireAuth(cfg)

	registry.RegisterMethod("system", "misc", "health", controller.Health)
	registry.RegisterMethod("system", "misc", "about", controller.About)
	registry.RegisterMethod("system", "misc", "machineips", requireAuth(controller.MachineIPs))
	registry.RegisterMethod("system", "misc", "subnetranges", requireAuth(controller.SubnetRanges))
	registry.RegisterMethod("system", "misc", "hasheschanged", requireAuth(controller.HashesChanged))

	log.Println("[MODULE] system registered")
}
