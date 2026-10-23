package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/l4r-s/krivy/internal/store"
)

// Scheduler enqueues periodic full-cluster scans.
type Scheduler struct {
	o        *Orchestrator
	st       store.Store
	schedule cron.Schedule
	spec     string
	log      *slog.Logger
	now      func() time.Time
	// startedAt anchors the first scan when there is no history and
	// scanOnStartup is false.
	startedAt     time.Time
	scanOnStartup bool
}

// ParseSchedule accepts standard 5-field cron, descriptors such as @daily,
// and "@every <duration>".
func ParseSchedule(spec string) (cron.Schedule, error) {
	p := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	s, err := p.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid scan schedule %q: %w", spec, err)
	}
	return s, nil
}

// NewScheduler returns nil when spec is empty (scheduling disabled). With no
// scan history the first scan runs immediately when scanOnStartup is set,
// otherwise one schedule interval after the controller starts.
func NewScheduler(o *Orchestrator, st store.Store, spec string, scanOnStartup bool, log *slog.Logger) (*Scheduler, error) {
	if spec == "" {
		return nil, nil
	}
	s, err := ParseSchedule(spec)
	if err != nil {
		return nil, err
	}
	return &Scheduler{o: o, st: st, schedule: s, spec: spec, log: log, now: o.opts.Now,
		startedAt: o.opts.Now(), scanOnStartup: scanOnStartup}, nil
}

// Due reports whether a scheduled scan is due given the last cluster run.
// The schedule is anchored at the last run so restarts don't skip or
// double-trigger scans.
func (s *Scheduler) Due(ctx context.Context) (bool, time.Time, error) {
	last, err := s.st.LatestScanRun(ctx, store.ScopeCluster, "")
	if errors.Is(err, store.ErrNotFound) {
		if s.scanOnStartup {
			return true, s.now(), nil
		}
		next := s.schedule.Next(s.startedAt)
		return !s.now().Before(next), next, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	next := s.schedule.Next(last.CreatedAt)
	return !s.now().Before(next), next, nil
}

// Run checks once a minute and enqueues a cluster scan when due.
func (s *Scheduler) Run(ctx context.Context) {
	s.log.Info("scan scheduler started", "schedule", s.spec)
	check := func() {
		due, next, err := s.Due(ctx)
		if err != nil {
			s.log.Error("scheduler", "error", err)
			return
		}
		if !due {
			s.log.Debug("next scheduled scan", "at", next)
			return
		}
		if _, _, err := s.o.Enqueue(ctx, store.ScopeCluster, "", store.TriggerSchedule, "scheduler"); err != nil {
			s.log.Error("enqueue scheduled scan", "error", err)
		}
	}
	check()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
