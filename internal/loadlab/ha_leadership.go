package loadlab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lindm/internal/devlab"
)

const (
	// maxLeadershipOverlap bounds how long a former leader may run after losing
	// its coordination session: one heartbeat plus one bounded probe, with margin.
	maxLeadershipOverlap = 10 * time.Second
	// maxLeadershipGap is the per-fault recovery bound for exclusive jobs, well
	// inside the documented five-minute HA recovery target.
	maxLeadershipGap = 2 * time.Minute
	maxHolderSamples = 20000
)

// HALeadership summarizes exclusive-job ownership from two independent
// sources: PostgreSQL's granted advisory locks and each replica's own log.
type HALeadership struct {
	Jobs                    []HAJobLeadership `json:"jobs"`
	LockSamples             int               `json:"lock_samples"`
	LockSampleErrors        int               `json:"lock_sample_errors"`
	MaxGapSeconds           float64           `json:"max_unheld_gap_seconds"`
	MaxOverlapSeconds       float64           `json:"max_overlap_seconds"`
	OverlapsOutsideFailover int               `json:"overlaps_outside_database_failover"`
	AllJobsHeldAtEnd        bool              `json:"all_jobs_held_at_end"`
	FinalHolders            map[string]string `json:"final_holders"`
	SessionLosses           map[string]int    `json:"coordination_session_losses"`
}

// HAJobLeadership is one exclusive job's ownership history.
type HAJobLeadership struct {
	Job               string           `json:"job"`
	Intervals         []HALeadInterval `json:"intervals"`
	MaxOverlapSeconds float64          `json:"max_overlap_seconds"`
}

// HALeadInterval is one replica incarnation's leadership of a job.
type HALeadInterval struct {
	Instance string    `json:"instance"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Ended    string    `json:"ended"`
}

type holderSample struct {
	at      time.Time
	holders []devlab.HALockHolder
	failed  bool
}

// holderSampler polls pg_locks on the current primary once per second.
type holderSampler struct {
	fixture *devlab.AuthorityFixture
	mu      sync.Mutex
	samples []holderSample
}

func newHolderSampler(fixture *devlab.AuthorityFixture) *holderSampler {
	return &holderSampler{fixture: fixture}
}

func (s *holderSampler) run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		holders, err := s.fixture.HALockHolders(probe)
		cancel()
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if len(s.samples) < maxHolderSamples {
			s.samples = append(s.samples, holderSample{at: time.Now().UTC(), holders: holders, failed: err != nil})
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *holderSampler) snapshot() []holderSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.samples)
}

type leadershipLog struct {
	Time   time.Time `json:"time"`
	Msg    string    `json:"msg"`
	Job    string    `json:"job"`
	Mode   string    `json:"mode"`
	Reason string    `json:"reason"`
}

// leadership reconciles replica logs, orchestration events and lock samples.
func (h *haRun) leadership(ctx context.Context, result *HAResult) (HALeadership, error) {
	summary := HALeadership{FinalHolders: make(map[string]string), SessionLosses: make(map[string]int)}
	exclusive := make(map[string]bool)
	intervals := make(map[string][]HALeadInterval)
	for _, name := range devlab.HAInstanceNames {
		data, err := h.fixture.HAInstanceLog(name)
		if err != nil {
			return summary, err
		}
		// Process ends close any interval the dead incarnation could not log.
		var ends []HAEvent
		for _, event := range h.events {
			if event.Target == name && (event.Kind == "kill" || event.Kind == "stop") {
				ends = append(ends, event)
			}
		}
		open := make(map[string]*HALeadInterval)
		closeAll := func(at time.Time, reason string) {
			for job, interval := range open {
				interval.To, interval.Ended = at, reason
				intervals[job] = append(intervals[job], *interval)
				delete(open, job)
			}
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for scanner.Scan() {
			var line leadershipLog
			if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Time.IsZero() {
				continue
			}
			line.Time = line.Time.UTC()
			for len(ends) > 0 && !ends[0].At.After(line.Time) {
				closeAll(ends[0].At, ends[0].Kind)
				ends = ends[1:]
			}
			switch line.Msg {
			case "background job leadership acquired":
				exclusive[line.Job] = true
				open[line.Job] = &HALeadInterval{Instance: name, From: line.Time}
			case "background job leadership released", "background job stopped; releasing leadership":
				if interval := open[line.Job]; interval != nil {
					interval.To, interval.Ended = line.Time, line.Reason
					if interval.Ended == "" {
						interval.Ended = "job_stopped"
					}
					intervals[line.Job] = append(intervals[line.Job], *interval)
					delete(open, line.Job)
				}
			case "job coordination session unavailable":
				summary.SessionLosses[name]++
			}
		}
		if err := scanner.Err(); err != nil {
			return summary, err
		}
		for _, end := range ends {
			closeAll(end.At, end.Kind)
		}
		closeAll(time.Now().UTC(), "running")
	}
	failoverFrom := result.Failover.KilledAt.Add(-time.Second)
	failoverTo := result.Failover.WritableAt.Add(30 * time.Second)
	jobs := make([]string, 0, len(intervals))
	for job := range intervals {
		jobs = append(jobs, job)
	}
	sort.Strings(jobs)
	for _, job := range jobs {
		list := intervals[job]
		sort.Slice(list, func(i, j int) bool { return list[i].From.Before(list[j].From) })
		leadership := HAJobLeadership{Job: job, Intervals: list}
		for i := range list {
			for j := i + 1; j < len(list); j++ {
				if list[i].Instance == list[j].Instance {
					continue
				}
				start, end := maxTime(list[i].From, list[j].From), minTime2(list[i].To, list[j].To)
				if !end.After(start) {
					continue
				}
				overlap := end.Sub(start).Seconds()
				leadership.MaxOverlapSeconds = max(leadership.MaxOverlapSeconds, overlap)
				if result.Failover.KilledAt.IsZero() || end.Before(failoverFrom) || start.After(failoverTo) {
					summary.OverlapsOutsideFailover++
				}
			}
		}
		summary.MaxOverlapSeconds = max(summary.MaxOverlapSeconds, leadership.MaxOverlapSeconds)
		summary.Jobs = append(summary.Jobs, leadership)
	}
	samples := h.holders.snapshot()
	summary.LockSamples = len(samples)
	// Gaps are measured per key from its first observed holder onward.
	firstHeld := make(map[int64]time.Time)
	lastHeld := make(map[int64]time.Time)
	for _, sample := range samples {
		if sample.failed {
			summary.LockSampleErrors++
			continue
		}
		for _, holder := range sample.holders {
			if _, ok := firstHeld[holder.Key]; !ok {
				firstHeld[holder.Key] = sample.at
			} else {
				summary.MaxGapSeconds = max(summary.MaxGapSeconds, sample.at.Sub(lastHeld[holder.Key]).Seconds())
			}
			lastHeld[holder.Key] = sample.at
		}
	}
	holders, err := h.fixture.HALockHolders(ctx)
	if err != nil {
		return summary, err
	}
	pids := make(map[string]string)
	for _, instance := range h.fixture.HAInstances() {
		pids[strconv.Itoa(instance.PID)] = instance.Name
	}
	held := make(map[int64]bool)
	for _, holder := range holders {
		owner := holder.ApplicationName
		if index := strings.LastIndex(owner, " pid "); index >= 0 {
			if name, ok := pids[owner[index+len(" pid "):]]; ok {
				owner = name
			}
		}
		summary.FinalHolders[strconv.FormatInt(holder.Key, 16)] = owner
		held[holder.Key] = true
	}
	summary.AllJobsHeldAtEnd = len(exclusive) > 0 && len(held) == len(exclusive)
	for _, owner := range summary.FinalHolders {
		if owner != devlab.HAInstanceNames[0] && owner != devlab.HAInstanceNames[1] {
			summary.AllJobsHeldAtEnd = false
		}
	}
	return summary, nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime2(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
