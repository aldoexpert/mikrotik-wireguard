package core

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
)

// App wires together configuration, the dynamic router and the registry
// every module registers its controllers into.
type App struct {
	Config   *config.App
	Router   *Router
	Registry *Registry
	Server   *http.Server
}

// NewApp creates the application shell. Modules are registered onto
// app.Registry afterwards, from cmd/api/main.go.
func NewApp(cfg *config.App) *App {
	registry := NewRegistry()
	router := NewRouter(registry, cfg.BasePath)

	return &App{
		Config:   cfg,
		Router:   router,
		Registry: registry,
	}
}

// Run starts the HTTP server with the given handler (the router wrapped in
// whatever middleware stack main.go assembled) and blocks until shut down.
// Middleware wrapping lives outside this package to avoid an import cycle
// (middleware depends on core's response helpers).
func (a *App) Run(h http.Handler) error {
	addr := fmt.Sprintf(":%d", a.Config.Port)

	a.Server = &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		log.Println("[APP] Received shutdown signal...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.Server.Shutdown(ctx); err != nil {
			log.Printf("[APP] Error during shutdown: %v", err)
		}
	}()

	log.Printf("========================================")
	log.Printf("[APP] %s", a.Config.Name)
	log.Printf("[APP] Version   : %s (%s)", a.Config.AppVersion, a.Config.GitCommit)
	log.Printf("[APP] Port      : %d", a.Config.Port)
	log.Printf("[APP] Debug     : %v", a.Config.Debug)
	log.Printf("[APP] Login     : %v", !a.Config.DisableLogin)
	log.Printf("[APP] Server running at http://localhost%s", addr)
	log.Printf("========================================")

	if err := a.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error running the server: %v", err)
	}

	log.Println("[APP] Server shut down cleanly")
	return nil
}
