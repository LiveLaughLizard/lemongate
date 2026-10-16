package ui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lemongate/internal/store"
)

// Form helpers read optional typed values from a parsed form.

func FormStr(r *http.Request, k string) string { return strings.TrimSpace(r.FormValue(k)) }

func FormFloatPtr(r *http.Request, k string) *float64 {
	v := FormStr(r, k)
	if v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(strings.TrimPrefix(v, "$"), 64)
	if err != nil {
		return nil
	}
	return &f
}

func FormFloat(r *http.Request, k string) float64 {
	if p := FormFloatPtr(r, k); p != nil {
		return *p
	}
	return 0
}

func FormIntPtr(r *http.Request, k string) *int {
	v := FormStr(r, k)
	if v == "" {
		return nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &i
}

func FormInt(r *http.Request, k string, def int) int {
	if p := FormIntPtr(r, k); p != nil {
		return *p
	}
	return def
}

func FormBool(r *http.Request, k string) bool {
	v := strings.ToLower(FormStr(r, k))
	return v == "on" || v == "true" || v == "1" || v == "yes"
}

// FormList reads multi-value fields and comma/newline-separated text.
func FormList(r *http.Request, k string) []string {
	var raw []string
	for _, v := range r.Form[k] {
		raw = append(raw, strings.Split(strings.ReplaceAll(v, "\n", ","), ",")...)
	}
	return store.CleanList(raw)
}

// FormDatePtr parses <input type="date"> (end of day UTC) or a duration like "30d".
func FormDatePtr(r *http.Request, k string) *time.Time {
	v := FormStr(r, k)
	if v == "" {
		return nil
	}
	if d, ok := store.ParseDuration(v); ok {
		t := time.Now().Add(d)
		return &t
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return nil
	}
	t = t.Add(24*time.Hour - time.Second)
	return &t
}

// FormJSONMap parses a JSON object textarea (empty → {}).
func FormJSONMap(r *http.Request, k string) (map[string]any, error) {
	v := FormStr(r, k)
	m := map[string]any{}
	if v == "" {
		return m, nil
	}
	err := json.Unmarshal([]byte(v), &m)
	return m, err
}

// FormStringMap parses "Key: value" lines or a JSON object into a string map.
func FormStringMap(r *http.Request, k string) map[string]string {
	v := FormStr(r, k)
	m := map[string]string{}
	if v == "" {
		return m
	}
	if strings.HasPrefix(v, "{") {
		_ = json.Unmarshal([]byte(v), &m)
		return m
	}
	for _, line := range strings.Split(v, "\n") {
		if i := strings.IndexAny(line, ":="); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}
