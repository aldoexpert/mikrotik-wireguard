// Package auth exposes the login/logout/profile endpoints used by the
// frontend to establish and refresh a session.
package auth

import (
	"log"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

// Register wires the "auth" module's endpoints into registry.
//
//	POST /auth/session/login   (public)
//	POST /auth/session/logout  (authenticated)
//	GET  /auth/session/profile (authenticated)
//	GET  /auth/session/menu    (authenticated) -- menu groups every module
//	                                              registered, filtered by role
func Register(registry *core.Registry, cfg *config.App, db store.IStore) {
	controller := NewSessionController(cfg, db, registry)
	registry.RegisterController("auth", "session", controller)

	requireAuth := middleware.RequireAuth(cfg)

	registry.RegisterMethod("auth", "session", "login", controller.Login)
	registry.RegisterMethod("auth", "session", "logout", requireAuth(controller.Logout))
	registry.RegisterMethod("auth", "session", "profile", requireAuth(controller.Profile))
	registry.RegisterMethod("auth", "session", "menu", requireAuth(controller.Menu))

	log.Println("[MODULE] auth registered")
}
