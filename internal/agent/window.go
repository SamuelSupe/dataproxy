package agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type accessWindowRule struct {
	raw        string
	days       [7]bool // Indexed by time.Weekday (Sunday=0 .. Saturday=6)
	startMin   int     // Minutes since 00:00 [0..1439]
	endMin     int     // Minutes since 00:00 [0..1440]
	overnight  bool    // True when startMin > endMin (e.g. 22:00-02:00)
}

// TimeWindowChecker enforces local tenant access schedules (e.g. "00:00-06:00", "Mon-Fri 22:00-02:00").
// A nil checker or empty rule list allows access at all times.
type TimeWindowChecker struct {
	loc   *time.Location
	rules []accessWindowRule
	raw   []string
	nowFn func() time.Time // Overridable in tests
}

// NewTimeWindowChecker parses a list of window expressions in the specified IANA timezone.
func NewTimeWindowChecker(windows []string, tzName string) (*TimeWindowChecker, error) {
	if len(windows) == 0 {
		return nil, nil
	}
	loc := time.Local
	if strings.TrimSpace(tzName) != "" {
		var err error
		loc, err = time.LoadLocation(strings.TrimSpace(tzName))
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %q: %w", tzName, err)
		}
	}

	rules := make([]accessWindowRule, 0, len(windows))
	for _, w := range windows {
		rule, err := parseWindowRule(w)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return &TimeWindowChecker{
		loc:   loc,
		rules: rules,
		raw:   append([]string(nil), windows...),
		nowFn: time.Now,
	}, nil
}

// Allowed reports whether the current time (or now if provided via AllowedAt) falls within
// at least one configured access window.
func (c *TimeWindowChecker) Allowed() (bool, string) {
	if c == nil || len(c.rules) == 0 {
		return true, ""
	}
	return c.AllowedAt(c.nowFn())
}

// AllowedAt evaluates whether t falls inside any configured window in c.loc.
func (c *TimeWindowChecker) AllowedAt(t time.Time) (bool, string) {
	if c == nil || len(c.rules) == 0 {
		return true, ""
	}
	localT := t.In(c.loc)
	curMin := localT.Hour()*60 + localT.Minute()
	today := localT.Weekday()
	yesterday := (today + 6) % 7

	for _, r := range c.rules {
		if !r.overnight {
			if r.days[today] && curMin >= r.startMin && curMin < r.endMin {
				return true, ""
			}
		} else {
			// Overnight window e.g. 22:00-02:00:
			// Matches if today is allowed and curMin >= startMin, OR yesterday was allowed and curMin < endMin.
			if (r.days[today] && curMin >= r.startMin) || (r.days[yesterday] && curMin < r.endMin) {
				return true, ""
			}
		}
	}

	return false, fmt.Sprintf(
		"access denied outside allowed_windows %v (current time %s %s)",
		c.raw,
		localT.Format("Mon 15:04"),
		c.loc.String(),
	)
}

func parseWindowRule(expr string) (accessWindowRule, error) {
	raw := strings.TrimSpace(expr)
	if raw == "" {
		return accessWindowRule{}, fmt.Errorf("empty access window expression")
	}
	fields := strings.Fields(raw)
	var days [7]bool
	var timePart string

	switch len(fields) {
	case 1:
		for i := range days {
			days[i] = true
		}
		timePart = fields[0]
	case 2:
		parsedDays, err := parseDaysSpec(fields[0])
		if err != nil {
			return accessWindowRule{}, fmt.Errorf("window %q: %w", raw, err)
		}
		days = parsedDays
		timePart = fields[1]
	default:
		return accessWindowRule{}, fmt.Errorf("invalid access window %q (expected 'HH:MM-HH:MM' or 'Mon-Fri HH:MM-HH:MM')", raw)
	}

	startStr, endStr, ok := strings.Cut(timePart, "-")
	if !ok {
		return accessWindowRule{}, fmt.Errorf("invalid time range %q in window %q", timePart, raw)
	}
	startMin, err := parseHHMM(startStr, false)
	if err != nil {
		return accessWindowRule{}, fmt.Errorf("window %q start time: %w", raw, err)
	}
	endMin, err := parseHHMM(endStr, true)
	if err != nil {
		return accessWindowRule{}, fmt.Errorf("window %q end time: %w", raw, err)
	}
	if startMin == endMin {
		return accessWindowRule{}, fmt.Errorf("window %q start and end time cannot be equal", raw)
	}

	return accessWindowRule{
		raw:       raw,
		days:      days,
		startMin:  startMin,
		endMin:    endMin,
		overnight: startMin > endMin,
	}, nil
}

func parseHHMM(s string, allow24 bool) (int, error) {
	hStr, mStr, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	h, err1 := strconv.Atoi(hStr)
	m, err2 := strconv.Atoi(mStr)
	if err1 != nil || err2 != nil || m < 0 || m > 59 || h < 0 {
		return 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	if allow24 && h == 24 && m == 0 {
		return 1440, nil
	}
	if h > 23 {
		return 0, fmt.Errorf("hour out of range in %q", s)
	}
	return h*60 + m, nil
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

func parseDaysSpec(spec string) ([7]bool, error) {
	var days [7]bool
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if aStr, bStr, isRange := strings.Cut(part, "-"); isRange {
			a, ok1 := weekdayNames[strings.ToLower(strings.TrimSpace(aStr))]
			b, ok2 := weekdayNames[strings.ToLower(strings.TrimSpace(bStr))]
			if !ok1 || !ok2 {
				return days, fmt.Errorf("invalid weekday range %q", part)
			}
			for d := a; ; d = (d + 1) % 7 {
				days[d] = true
				if d == b {
					break
				}
			}
		} else {
			d, ok := weekdayNames[strings.ToLower(part)]
			if !ok {
				return days, fmt.Errorf("invalid weekday %q", part)
			}
			days[d] = true
		}
	}
	return days, nil
}
