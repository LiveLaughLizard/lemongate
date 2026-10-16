package web

import (
	"io/fs"
	"testing"
)

// Partials live in files named _*.html, which go:embed skips unless the pattern uses all:.
func TestEmbedIncludesPartials(t *testing.T) {
	files, err := fs.Glob(FS(""), "templates/pages/*/_*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("embedded templates are missing partials (%v)", err)
	}
}
