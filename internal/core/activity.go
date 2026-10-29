package core

import "time"

// Activity is the number of distinct devices online in each hour of a
// window, oldest hour first. Hours are aligned to UTC hour boundaries,
// which are local hour boundaries in every whole-hour time zone.
type Activity struct {
	Start  time.Time `json:"start"`
	Hourly []int     `json:"hourly"`
}

// Activity counts devices online per hour over the last days, up to and
// including the current hour.
func (r *Registry) Activity(days int) (Activity, error) {
	now := r.o.Now()
	end := now.Truncate(time.Hour).Add(time.Hour)
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	sessions, err := r.o.Store.AllSessions(start)
	if err != nil {
		return Activity{}, err
	}
	n := int(end.Sub(start) / time.Hour)
	seen := make([]map[int64]bool, n)
	for _, s := range sessions {
		from, to := s.Start, s.End
		if to.IsZero() || to.After(now) {
			to = now
		}
		if from.Before(start) {
			from = start
		}
		if !to.After(from) {
			to = from // a single sighting still counts for its hour
		}
		first := int(from.Sub(start) / time.Hour)
		last := int(to.Sub(start) / time.Hour)
		for h := first; h <= last && h < n; h++ {
			if h < 0 {
				continue
			}
			if seen[h] == nil {
				seen[h] = map[int64]bool{}
			}
			seen[h][s.DeviceID] = true
		}
	}
	a := Activity{Start: start, Hourly: make([]int, n)}
	for i, m := range seen {
		a.Hourly[i] = len(m)
	}
	return a, nil
}
