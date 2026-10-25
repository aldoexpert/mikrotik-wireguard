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
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}
