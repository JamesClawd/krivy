package findings

import (
	"strings"
	"time"

	"github.com/l4r-s/krivy/internal/store"
)

// Policy decides whether a finding should alert, given active silences.
//
// Acknowledgement suppresses repeat alerts for a finding but keeps it
// visible. Silences suppress alerts for matching findings until they expire
// or are revoked. A brand-new finding is never acknowledged, so it alerts
// unless an explicit silence covers it.
type Policy struct {
	silences []store.Silence
	now      time.Time
}

// NewPolicy builds a policy from silences; inactive ones are ignored.
func NewPolicy(silences []store.Silence, now time.Time) *Policy {
	p := &Policy{now: now}
	for _, s := range silences {
		if s.ActiveAt(now) {
			p.silences = append(p.silences, s)
		}
	}
	return p
}

// SilencedBy returns the IDs of silences covering the finding. namespaces
// are the namespaces where the finding's image is actively deployed.
func (p *Policy) SilencedBy(f *store.Finding, repository string, namespaces []string) []string {
	var ids []string
	for i := range p.silences {
		if Matches(&p.silences[i], f, repository, namespaces) {
			ids = append(ids, p.silences[i].ID)
		}
	}
	if len(ids) > 0 {
		return ids
	}
	// Namespace silences only cover a finding when every namespace using the
	// image is silenced; a shared image still alerts for other namespaces.
	if len(namespaces) > 0 {
		var nsIDs []string
		for _, ns := range namespaces {
			found := ""
			for i := range p.silences {
				s := &p.silences[i]
				if s.Kind == store.SilenceNamespace && s.Target == ns {
					found = s.ID
					break
				}
			}
			if found == "" {
				return nil
			}
			nsIDs = append(nsIDs, found)
		}
		return dedupe(nsIDs)
	}
	return nil
}

// ShouldAlertNew reports whether a newly found or reopened finding alerts.
func (p *Policy) ShouldAlertNew(f *store.Finding, repository string, namespaces []string) bool {
	if f.AcknowledgedAt != nil {
		return false
	}
	return len(p.SilencedBy(f, repository, namespaces)) == 0
}

// ShouldAlertResolved reports whether a resolution alerts (silenced findings
// stay quiet in both directions).
func (p *Policy) ShouldAlertResolved(f *store.Finding, repository string, namespaces []string) bool {
	return len(p.SilencedBy(f, repository, namespaces)) == 0
}

// Matches reports whether a non-namespace silence directly covers f.
// Image silences match the exact image key or, when the target has no digest,
// every digest of that repository.
func Matches(s *store.Silence, f *store.Finding, repository string, _ []string) bool {
	switch s.Kind {
	case store.SilenceFinding:
		return s.Target == f.ID
	case store.SilenceImage:
		if s.Target == f.ImageKey {
			return true
		}
		return repository != "" && !strings.Contains(s.Target, "@") && s.Target == repository
	case store.SilenceVulnerability:
		return strings.EqualFold(s.Target, f.VulnerabilityID)
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
