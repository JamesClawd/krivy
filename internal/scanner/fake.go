package scanner

import (
	"context"
	"sync"
	"time"
)

// Fake is an in-memory Scanner for tests. Results and Errors are keyed by
// Target.ImageRef; a ref in neither map yields an empty (clean) Result.
// Set the maps and Delay before calling Scan concurrently.
type Fake struct {
	Results map[string]*Result
	Errors  map[string]error
	// Delay is applied before each scan returns; ctx cancellation aborts it.
	Delay time.Duration

	mu    sync.Mutex
	calls []Target
}

var _ Scanner = (*Fake)(nil)

// NewFake returns a Fake with initialized maps.
func NewFake() *Fake {
	return &Fake{Results: map[string]*Result{}, Errors: map[string]error{}}
}

// Scan records the call and returns the configured outcome.
func (f *Fake) Scan(ctx context.Context, t Target) (*Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t)
	f.mu.Unlock()

	if f.Delay > 0 {
		timer := time.NewTimer(f.Delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err, ok := f.Errors[t.ImageRef]; ok && err != nil {
		return nil, err
	}
	out := &Result{ImageRef: t.ImageRef, JobName: "fake-" + t.ScanJobID, Vulnerabilities: []Vulnerability{}}
	if r, ok := f.Results[t.ImageRef]; ok && r != nil {
		cp := *r
		cp.Vulnerabilities = append([]Vulnerability{}, r.Vulnerabilities...)
		if cp.ImageRef == "" {
			cp.ImageRef = t.ImageRef
		}
		out = &cp
	}
	return out, nil
}

// Calls returns a copy of all recorded targets in call order.
func (f *Fake) Calls() []Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Target(nil), f.calls...)
}
