// Package web embeds templates and static assets into the binary.
package web

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed all:templates static
var embedded embed.FS

// FS returns the asset filesystem. With dir set (dev mode) files are read from disk
// so template and CSS edits apply without rebuilding.
func FS(dir string) fs.FS {
	if dir != "" {
		return os.DirFS(dir)
	}
	return embedded
}
