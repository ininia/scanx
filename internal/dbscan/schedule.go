package dbscan

import "time"

// Schedules.
const (
	ScheduleOff    = "off"
	ScheduleHourly = "hourly"
	ScheduleDaily  = "daily"
	ScheduleWeekly = "weekly"
)

// ValidSchedule reports whether s is a known schedule.
func ValidSchedule(s string) bool {
	return s == ScheduleOff || s == ScheduleHourly || s == ScheduleDaily || s == ScheduleWeekly
}

// NextRun is the first run strictly after `after` in loc: hourly at
// minute 0, daily at hour:00, weekly on weekday (0 = Sunday) at hour:00.
// nil when the schedule is off.
func NextRun(schedule string, hour, weekday int, after time.Time, loc *time.Location) *time.Time {
	if loc == nil {
		loc = time.UTC
	}
	t := after.In(loc)
	var next time.Time
	switch schedule {
	case ScheduleHourly:
		next = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, loc).Add(time.Hour)
	case ScheduleDaily:
		next = time.Date(t.Year(), t.Month(), t.Day(), hour, 0, 0, 0, loc)
		if !next.After(t) {
			next = next.AddDate(0, 0, 1)
		}
	case ScheduleWeekly:
		next = time.Date(t.Year(), t.Month(), t.Day(), hour, 0, 0, 0, loc)
		next = next.AddDate(0, 0, (weekday-int(next.Weekday())+7)%7)
		if !next.After(t) {
			next = next.AddDate(0, 0, 7)
		}
	default:
		return nil
	}
	u := next.UTC()
	return &u
}
