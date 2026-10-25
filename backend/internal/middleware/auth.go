package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/handler"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
)

type contextKey string

const claimsContextKey contextKey = "claims"

// RequireAuth wraps a ControllerMethod so it only runs for requests
// carrying a valid "Authorization: Bearer <token>" JWT. When cfg.DisableLogin
// is set (dev only) it bypasses the check entirely, same as upstream
// wireguard-ui's --disable-login flag.
func RequireAuth(cfg *config.App) func(handler.ControllerMethod) handler.ControllerMethod {
	return func(next handler.ControllerMethod) handler.ControllerMethod {
		return func(w http.ResponseWriter, r *http.Request, params []string) {
			if cfg.DisableLogin {
				// Login disabled (dev only): act as a synthetic admin, same
				// semantics as upstream wireguard-ui's --disable-login.
				ctx := context.WithValue(r.Context(), claimsContextKey, &library.Claims{Admin: true})
				next(w, r.WithContext(ctx), params)
				return
			}

			claims, ok := parseAuthHeader(cfg, r)
			if !ok {
				core.Unauthorized(w, "Invalid session, please log in again")
				return
			}

			// Reject if the user was changed/removed since the token was issued.
			if currentHash, found := library.UserHash(claims.Username); !found || currentHash != claims.UserHash {
				core.Unauthorized(w, "Invalid session, please log in again")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next(w, r.WithContext(ctx), params)
		}
	}
}

// RequireAdmin must be chained inside RequireAuth: RequireAuth(cfg)(RequireAdmin(handler)).
func RequireAdmin(next handler.ControllerMethod) handler.ControllerMethod {
	return func(w http.ResponseWriter, r *http.Request, params []string) {
		if !IsAdmin(r) {
			core.Forbidden(w, "Only an admin can access this endpoint")
			return
		}
		next(w, r, params)
	}
}

func parseAuthHeader(cfg *config.App, r *http.Request) (*library.Claims, bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, false
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := library.ParseToken(cfg.JWTSecret, tokenString)
	if err != nil {
		return nil, false
	}
	return claims, true
}

// CurrentUsername returns the username carried by the request's JWT, or ""
// when authentication is disabled / not yet resolved.
func CurrentUsername(r *http.Request) string {
	claims, ok := r.Context().Value(claimsContextKey).(*library.Claims)
	if !ok {
		return ""
	}
	return claims.Username
}

// IsAdmin returns whether the request's JWT belongs to an admin user.
func IsAdmin(r *http.Request) bool {
	claims, ok := r.Context().Value(claimsContextKey).(*library.Claims)
	if !ok {
		return false
	}
	return claims.Admin
}
