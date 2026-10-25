package core

import (
	"log"
	"net/http"
	"strings"
)

// Router dispatches "/module/controller/method/param1/param2..." requests to
// the handler registered for that module/controller/method triple. The HTTP
// verb is not part of the dispatch key -- same convention as AEFW: the method
// name itself (list/get/create/update/delete/...) carries the action.
type Router struct {
	registry *Registry
	basePath string
}

// NewRouter creates a router bound to registry. basePath, if non-empty, is
// stripped from the request path before parsing (useful when the API is
// mounted under a sub-path behind a reverse proxy).
func NewRouter(registry *Registry, basePath string) *Router {
	return &Router{registry: registry, basePath: strings.Trim(basePath, "/")}
}

// ServeHTTP implements http.Handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")

	if rt.basePath != "" {
		if !strings.HasPrefix(path, rt.basePath) {
			NotFound(w, "Invalid route")
			return
		}
		path = strings.Trim(strings.TrimPrefix(path, rt.basePath), "/")
	}

	if path == "" {
		h, exists := rt.registry.GetMethod("system", "misc", "health")
		if !exists {
			NotFound(w, "Endpoint not found")
			return
		}
		h(w, r, []string{})
		return
	}

	segments := strings.Split(path, "/")
	if len(segments) < 3 {
		NotFound(w, "Invalid route, use the /module/controller/method format")
		return
	}

	module, controller, method := segments[0], segments[1], segments[2]
	params := []string{}
	if len(segments) > 3 {
		params = segments[3:]
	}

	h, exists := rt.registry.GetMethod(module, controller, method)
	if !exists {
		log.Printf("[ROUTER] Method not found: %s/%s/%s", module, controller, method)
		NotFound(w, "Endpoint not found")
		return
	}

	log.Printf("[ROUTER] %s %s/%s/%s (params: %v)", r.Method, module, controller, method, params)
	h(w, r, params)
}
