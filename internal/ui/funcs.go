package ui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"lemongate/internal/auth"
)

var iconCache sync.Map

// Icon renders an inline Lucide SVG icon by name.
func Icon(assets fs.FS, name string, class ...string) template.HTML {
	key := name + "|" + strings.Join(class, " ")
	if v, ok := iconCache.Load(key); ok {
		return v.(template.HTML)
	}
	raw, err := fs.ReadFile(assets, "static/dist/icons/"+name+".svg")
	if err != nil {
		return template.HTML(`<span class="lg-icon"></span>`)
	}
	svg := string(raw)
	if i := strings.Index(svg, "<svg"); i >= 0 {
		svg = svg[i:]
	}
	svg = strings.Replace(svg, `class="lucide`, `aria-hidden="true" class="lucide`, 1)
	cls := "lg-icon"
	if len(class) > 0 {
		cls += " " + strings.Join(class, " ")
	}
	out := template.HTML(`<span class="` + template.HTMLEscapeString(cls) + `">` + svg + `</span>`)
	iconCache.Store(key, out)
	return out
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case nil:
		return 0
	case float64:
		return n
	case *float64:
		if n == nil {
			return 0
		}
		return *n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case *int:
		if n == nil {
			return 0
		}
		return float64(*n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}

func Money(v any) string {
	f := toFloat(v)
	switch {
	case f == 0:
		return "$0.00"
	case math.Abs(f) < 0.0001:
		return "<$0.0001"
	case math.Abs(f) < 0.01:
		return "$" + strconv.FormatFloat(f, 'f', 4, 64)
	}
	return "$" + Num(math.Round(f*100)/100, 2)
}

// Num formats with thousands separators and the given decimals.
func Num(v any, decimals ...int) string {
	d := 0
	if len(decimals) > 0 {
		d = decimals[0]
	}
	f := toFloat(v)
	s := strconv.FormatFloat(math.Abs(f), 'f', d, 64)
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	var b strings.Builder
	for i, c := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	sign := ""
	if f < 0 {
		sign = "-"
	}
	return sign + b.String() + frac
}

func Compact(v any) string {
	f := toFloat(v)
	a := math.Abs(f)
	switch {
	case a >= 1e9:
		return strconv.FormatFloat(f/1e9, 'f', 1, 64) + "B"
	case a >= 1e6:
		return strconv.FormatFloat(f/1e6, 'f', 1, 64) + "M"
	case a >= 1e4:
		return strconv.FormatFloat(f/1e3, 'f', 1, 64) + "k"
	}
	return Num(f)
}

func Ago(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case *time.Time:
		if x == nil {
			return "never"
		}
		t = *x
	default:
		return ""
	}
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = "just now"
		return s
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		s = fmt.Sprintf("%dh", int(d.Hours()))
	case d < 30*24*time.Hour:
		s = fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 365*24*time.Hour:
		s = fmt.Sprintf("%dmo", int(d.Hours()/24/30))
	default:
		s = fmt.Sprintf("%dy", int(d.Hours()/24/365))
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

func DateTime(v any) string {
	switch x := v.(type) {
	case time.Time:
		if x.IsZero() {
			return "—"
		}
		return x.Local().Format("Jan 2, 2006 15:04")
	case *time.Time:
		if x == nil {
			return "—"
		}
		return x.Local().Format("Jan 2, 2006 15:04")
	}
	return ""
}

// InputDate formats a time for <input type="date">.
func InputDate(v any) string {
	switch x := v.(type) {
	case time.Time:
		return x.Format("2006-01-02")
	case *time.Time:
		if x != nil {
			return x.Format("2006-01-02")
		}
	}
	return ""
}

// Val renders optional numbers for form inputs ("" when nil).
func Val(v any) string {
	switch x := v.(type) {
	case *float64:
		if x == nil {
			return ""
		}
		return strconv.FormatFloat(*x, 'f', -1, 64)
	case *int:
		if x == nil {
			return ""
		}
		return strconv.Itoa(*x)
	case *string:
		if x == nil {
			return ""
		}
		return *x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case string:
		return x
	}
	return ""
}

func Has(list any, v any) bool {
	rv := reflect.ValueOf(list)
	if rv.Kind() != reflect.Slice {
		return false
	}
	for i := 0; i < rv.Len(); i++ {
		if reflect.DeepEqual(rv.Index(i).Interface(), v) {
			return true
		}
	}
	return false
}

func Dict(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return m
}

func ToJSON(v any) template.JS {
	b, _ := json.Marshal(v)
	return template.JS(b)
}

func PrettyJSON(v any) string {
	switch x := v.(type) {
	case []byte:
		var m any
		if json.Unmarshal(x, &m) == nil {
			v = m
		} else {
			return string(x)
		}
	case string:
		var m any
		if json.Unmarshal([]byte(x), &m) == nil {
			v = m
		} else {
			return x
		}
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Pct returns used/limit as 0-100 (capped), or -1 for no limit.
func Pct(used any, limit any) float64 {
	l := toFloat(limit)
	if limit == nil || l <= 0 || (reflect.ValueOf(limit).Kind() == reflect.Pointer && reflect.ValueOf(limit).IsNil()) {
		return -1
	}
	return math.Min(100, toFloat(used)/l*100)
}

// PctClass picks a progress color for a utilization percentage.
func PctClass(p float64) string {
	switch {
	case p >= 90:
		return "progress-error"
	case p >= 70:
		return "progress-warning"
	}
	return "progress-success"
}

func Initials(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "?"
	}
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '.' || r == '_' || r == '-' })
	out := ""
	for _, p := range parts {
		out += strings.ToUpper(string([]rune(p)[0]))
		if len(out) == 2 {
			break
		}
	}
	return out
}

func StatusClass(s string) string {
	switch s {
	case "success", "ok", "healthy", "active", "enabled":
		return "badge-success"
	case "error", "failed", "down", "unhealthy", "critical":
		return "badge-error"
	case "blocked", "warning", "cooldown", "expired":
		return "badge-warning"
	}
	return "badge-ghost"
}

func (r *Renderer) funcs() template.FuncMap {
	return template.FuncMap{
		"icon":        func(name string, class ...string) template.HTML { return Icon(r.fs, name, class...) },
		"money":       Money,
		"num":         Num,
		"compact":     Compact,
		"ago":         Ago,
		"dt":          DateTime,
		"inputDate":   InputDate,
		"val":         Val,
		"has":         Has,
		"dict":        Dict,
		"list":        func(v ...any) []any { return v },
		"json":        ToJSON,
		"pretty":      PrettyJSON,
		"truncate":    Truncate,
		"pct":         Pct,
		"pctClass":    PctClass,
		"initials":    Initials,
		"statusClass": StatusClass,
		"roleLabel":   auth.RoleLabel,
		"join":        func(sep string, s []string) string { return strings.Join(s, sep) },
		"joinc":       func(s []string) string { return strings.Join(s, ", ") },
		"upper":       strings.ToUpper,
		"lower":       strings.ToLower,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + strings.ReplaceAll(s[1:], "_", " ")
		},
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"derefF": func(f *float64) float64 {
			if f == nil {
				return 0
			}
			return *f
		},
		"derefI": func(i *int) int {
			if i == nil {
				return 0
			}
			return *i
		},
		"add":  func(a, b int) int { return a + b },
		"sub":  func(a, b int) int { return a - b },
		"mulf": func(a, b any) float64 { return toFloat(a) * toFloat(b) },
		"divf": func(a, b any) float64 {
			if toFloat(b) == 0 {
				return 0
			}
			return toFloat(a) / toFloat(b)
		},
		"seq": func(n int) []int {
			s := make([]int, n)
			for i := range s {
				s[i] = i
			}
			return s
		},
		"sorted":   func(s []string) []string { c := slices.Clone(s); slices.Sort(c); return c },
		"now":      time.Now,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"safeURL":  func(s string) template.URL { return template.URL(s) },
		"periodLabel": func(p string) string {
			if p == "" {
				return "lifetime"
			}
			return p
		},
		"isNil": func(v any) bool {
			if v == nil {
				return true
			}
			rv := reflect.ValueOf(v)
			switch rv.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
				return rv.IsNil()
			}
			return false
		},
	}
}
