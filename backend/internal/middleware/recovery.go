package middleware

import (
	"log"
	"net/http"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
)

// Recovery turns a panic in any handler into a 500 response instead of
// crashing the whole server.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] %s %s: %v", r.Method, r.URL.Path, rec)
				core.InternalError(w, "Terjadi kesalahan pada server", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
