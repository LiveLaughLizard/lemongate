package api

import (
	"bytes"
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"lemongate/internal/ui"
)

//go:embed docs.html.tmpl
var docsTmpl string

type docsRoute struct {
	ID      string
	Method  string
	Path    string
	Summary string
	Desc    template.HTML
	Access  string
	Query   []qparam
	Body    string
	Example string
	Curl    string
}

type docsGroup struct {
	Tag    string
	Desc   string
	Routes []docsRoute
}

type docsData struct {
	AppName string
	Version string
	BaseURL string
	Groups  []docsGroup
	Count   int
	Icons   map[string]template.HTML
}

var codeSpan = regexp.MustCompile("`([^`]+)`")

// inlineMarkdown escapes text and renders `code` spans.
func inlineMarkdown(s string) template.HTML {
	esc := template.HTMLEscapeString(s)
	esc = codeSpan.ReplaceAllString(esc, `<code class="rounded bg-base-200 px-1 py-0.5 font-mono text-[0.85em]">$1</code>`)
	return template.HTML(strings.ReplaceAll(esc, "\n\n", "<br><br>"))
}

func accessLabel(rt route) string {
	switch rt.Access {
	case accessSelf:
		return "Any management key"
	case accessViewer:
		if rt.Method == http.MethodGet {
			return "Admin or admin viewer"
		}
		return "Admin"
	}
	return "Admin"
}

func curlFor(base string, rt route) string {
	path := pathParam.ReplaceAllStringFunc(rt.Path, func(m string) string { return "<" + strings.Trim(m, "{}") + ">" })
	var b strings.Builder
	b.WriteString("curl")
	if rt.Method != http.MethodGet {
		b.WriteString(" -X " + rt.Method)
	}
	b.WriteString(" " + base + "/api/v1" + path + " \\\n  -H \"Authorization: Bearer $LEMONGATE_KEY\"")
	if rt.Body != "" {
		ex := rt.Example
		if ex == "" {
			ex = "{}"
		}
		b.WriteString(" \\\n  -H \"Content-Type: application/json\" \\\n  -d '" + ex + "'")
	}
	return b.String()
}

func (h *H) docsHandler(table []route) http.HandlerFunc {
	t := template.Must(template.New("docs").Parse(docsTmpl))
	return func(w http.ResponseWriter, r *http.Request) {
		base := strings.TrimRight(h.d.Cfg.BaseURL, "/")
		data := docsData{AppName: h.d.Settings.Current().Branding.AppName, Version: h.d.R.Version, BaseURL: base, Count: len(table)}
		if data.AppName == "" {
			data.AppName = "LemonGate"
		}
		// The asset build bundles icons it finds as: icon "book-open" icon "key-round" icon "file-json"
		// icon "arrow-left" icon "lock-keyhole" icon "copy" icon "sun-moon"
		assets := h.d.R.Assets()
		data.Icons = map[string]template.HTML{
			"book":  ui.Icon(assets, "book-open"),
			"key":   ui.Icon(assets, "key-round"),
			"json":  ui.Icon(assets, "file-json"),
			"back":  ui.Icon(assets, "arrow-left"),
			"lock":  ui.Icon(assets, "lock-keyhole"),
			"copy":  ui.Icon(assets, "copy"),
			"theme": ui.Icon(assets, "sun-moon"),
		}
		for _, tag := range sortedTags(table) {
			g := docsGroup{Tag: tag}
			for _, ti := range tagInfo {
				if ti.Name == tag {
					g.Desc = ti.Desc
				}
			}
			for _, rt := range table {
				if rt.Tag != tag {
					continue
				}
				g.Routes = append(g.Routes, docsRoute{ID: opID(rt), Method: rt.Method, Path: "/api/v1" + rt.Path, Summary: rt.Summary,
					Desc: inlineMarkdown(rt.Desc), Access: accessLabel(rt), Query: rt.Query, Body: rt.Body, Example: rt.Example, Curl: curlFor(base, rt)})
			}
			data.Groups = append(data.Groups, g)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			slog.Error("api docs", "err", err)
			http.Error(w, "template error", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = buf.WriteTo(w)
	}
}
