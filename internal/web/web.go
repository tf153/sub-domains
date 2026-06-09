// Package web holds the embedded static assets for the subscope web UI.
package web

import _ "embed"

// IndexHTML is the single-page UI served at "/".
//
//go:embed index.html
var IndexHTML []byte
