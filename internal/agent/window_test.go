package agent

import (
	"testing"
	"time"
)

func TestTimeWindowChecker(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("load tz: %v", err)
	}

	// Same-day window: 00:00-06:00
	w1, err := NewTimeWindowChecker([]string{"00:00-06:00"}, "Asia/Shanghai")
	if err != nil {
		t.Fatalf("parse w1: %v", err)
	}
	if ok, _ := w1.AllowedAt(time.Date(2026, 11, 25, 2, 30, 0, 0, shanghai)); !ok {
		t.Fatalf("expected 02:30 inside 00:00-06:00")
	}
	if ok, _ := w1.AllowedAt(time.Date(2026, 11, 25, 14, 0, 0, 0, shanghai)); ok {
		t.Fatalf("expected 14:00 outside 00:00-06:00")
	}

	// Overnight + weekday window: Mon-Fri 22:00-02:00
	w2, err := NewTimeWindowChecker([]string{"Mon-Fri 22:00-02:00"}, "Asia/Shanghai")
	if err != nil {
		t.Fatalf("parse w2: %v", err)
	}
	// Friday 23:15 -> ALLOWED
	friNight := time.Date(2026, 11, 27, 23, 15, 0, 0, shanghai)
	if ok, _ := w2.AllowedAt(friNight); !ok {
		t.Fatalf("expected Friday 23:15 allowed in Mon-Fri 22:00-02:00")
	}
	// Saturday 01:30 (spillover from Friday night!) -> ALLOWED
	satEarly := time.Date(2026, 11, 28, 1, 30, 0, 0, shanghai)
	if ok, _ := w2.AllowedAt(satEarly); !ok {
		t.Fatalf("expected Saturday 01:30 spillover allowed in Mon-Fri 22:00-02:00")
	}
	// Saturday 23:30 -> DENIED
	satNight := time.Date(2026, 11, 28, 23, 30, 0, 0, shanghai)
	if ok, _ := w2.AllowedAt(satNight); ok {
		t.Fatalf("expected Saturday 23:30 denied in Mon-Fri 22:00-02:00")
	}
	// Monday 01:00 (Sunday night spillover, Sunday not in Mon-Fri) -> DENIED
	monEarly := time.Date(2026, 11, 23, 1, 0, 0, 0, shanghai)
	if ok, _ := w2.AllowedAt(monEarly); ok {
		t.Fatalf("expected Monday 01:00 denied in Mon-Fri 22:00-02:00")
	}
}
