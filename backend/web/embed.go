// Package web embeds the built frontend (frontend/www, see root Dockerfile)
// so a single binary can serve both the API and the SPA on one port.
package web

import "embed"

// FS holds the built frontend files (dist/). The committed index.html is a
// placeholder so `go build` works standalone without the frontend having
// been built first; the Docker image always overwrites it with the real
// build output before compiling.
//
//go:embed all:dist
var FS embed.FS
