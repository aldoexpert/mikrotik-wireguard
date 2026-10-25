package web

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves the embedded SPA. If a
// requested path doesn't match a built file (client-side routes like
// /clients or /server), it falls back to index.html so Framework7's router
// can handle it.
func Handler() http.Handler {
	sub, err := fs.Sub(FS, "dist")
	if err != nil {
		panic("web: failed to sub FS: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}

		if _, err := sub.Open(p); err != nil {
			// Only fall back to the SPA shell for client-side routes
			// (e.g. /clients/5/edit/, which have no file extension on
			// their last segment). A request for an actual asset
			// (/assets/<hash>.js, /manifest.json, ...) that doesn't
			// exist -- typically a stale browser/service-worker cache
			// still referencing a previous build's hashed filename --
			// must get a real 404, not index.html with a text/html
			// Content-Type: browsers reject that for <script
			// type="module">/manifest requests (strict MIME checking),
			// so the asset silently fails to load and the page renders
			// blank instead of erroring visibly.
			if looksLikeAssetPath(p) {
				http.NotFound(w, r)
				return
			}
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}

// looksLikeAssetPath reports whether p's last path segment has a file
// extension, i.e. it names a static file rather than a client-side route.
func looksLikeAssetPath(p string) bool {
	last := p
	if idx := strings.LastIndex(p, "/"); idx != -1 {
		last = p[idx+1:]
	}
	return strings.Contains(last, ".")
}
