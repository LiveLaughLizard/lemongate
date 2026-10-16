package store

import (
	"strconv"
	"strings"
	"time"
)

// Budget periods: "" (never resets), "daily", "weekly", "monthly", or a duration
// such as "12h", "7d", "30d".
var PeriodOptions = []string{"", "daily", "weekly", "monthly"}

// NextReset returns the next reset instant after now for the given period, or nil.
func NextReset(period string, now time.Time) *time.Time {
	now = now.UTC()
	var t time.Time
	switch strings.ToLower(strings.TrimSpace(period)) {
	case "":
		return nil
	case "daily":
		t = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	case "weekly":
		days := (8 - int(now.Weekday())) % 7
		if days == 0 {
			days = 7
		}
		t = time.Date(now.Year(), now.Month(), now.Day()+days, 0, 0, 0, 0, time.UTC)
	case "monthly":
		t = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	default:
		d, ok := ParseDuration(period)
		if !ok {
			return nil
		}
		t = now.Add(d)
	}
	return &t
}

// ParseDuration accepts Go durations plus a "d" (day) suffix, e.g. "30d", "1d12h".
func ParseDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, false
	}
	var total time.Duration
	if i := strings.Index(s, "d"); i > 0 {
		n, err := strconv.Atoi(s[:i])
		if err != nil {
			return 0, false
		}
		total = time.Duration(n) * 24 * time.Hour
		s = s[i+1:]
	}
	if s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, false
		}
		total += d
	}
	return total, total > 0
}
