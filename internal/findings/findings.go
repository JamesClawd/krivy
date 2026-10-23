// Package findings reconciles scan results into persistent findings and
// applies the acknowledgement / silence alerting policy.
package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/store"
)

// ID returns the stable finding identity for an image + vulnerability +
// package occurrence.
func ID(imageKey, vulnID, pkgName, pkgPath, installed string) string {
	h := sha256.New()
	for _, p := range []string{imageKey, vulnID, pkgName, pkgPath, installed} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Changes are the alert-relevant transitions produced by a reconciliation.
type Changes struct {
	// New contains findings created or reopened.
	New []store.Finding
	// Resolved contains findings that transitioned to resolved.
	Resolved []store.Finding
}

func (c *Changes) Add(o Changes) {
	c.New = append(c.New, o.New...)
	c.Resolved = append(c.Resolved, o.Resolved...)
}

// ReconcileImage applies a successful scan of imageKey: vulnerabilities seen
// are created/refreshed/reopened and open findings no longer reported are
// resolved as fixed. It must only be called for successful scans, and only
// touches findings of this image, so a namespace scan can never resolve
// findings of images it did not scan.
func ReconcileImage(ctx context.Context, st store.Store, runID, imageKey string, vulns []scanner.Vulnerability, now time.Time) (Changes, error) {
	var ch Changes
	err := st.Transaction(ctx, func(tx store.Store) error {
		existing, err := tx.ListFindingsByImage(ctx, imageKey)
		if err != nil {
			return err
		}
		byID := make(map[string]*store.Finding, len(existing))
		for i := range existing {
			byID[existing[i].ID] = &existing[i]
		}
		seen := map[string]bool{}
		for _, v := range vulns {
			id := ID(imageKey, v.VulnerabilityID, v.PkgName, v.PkgPath, v.InstalledVersion)
			if seen[id] {
				continue
			}
			seen[id] = true
			f, ok := byID[id]
			switch {
			case !ok:
				f = &store.Finding{
					ID:               id,
					ImageKey:         imageKey,
					VulnerabilityID:  v.VulnerabilityID,
					PkgName:          v.PkgName,
					PkgPath:          v.PkgPath,
					InstalledVersion: v.InstalledVersion,
					Status:           store.FindingOpen,
					FirstSeenAt:      now,
				}
				ch.New = append(ch.New, *f)
			case f.Status == store.FindingResolved:
				// A vulnerability that comes back is alert-worthy again, so the
				// previous acknowledgement does not carry over.
				f.Status = store.FindingOpen
				f.ReopenedAt = &now
				f.ResolvedAt = nil
				f.ResolutionReason = ""
				f.AcknowledgedAt = nil
				f.AckBy = ""
				f.AckReason = ""
				ch.New = append(ch.New, *f)
			}
			// Refresh mutable advisory data on every observation.
			f.FixedVersion = v.FixedVersion
			f.Severity = strings.ToUpper(v.Severity)
			f.Title = truncate(v.Title, 1024)
			f.PrimaryURL = truncate(v.PrimaryURL, 1024)
			f.LastSeenAt = now
			f.LastScanRunID = runID
			if err := tx.SaveFinding(ctx, f); err != nil {
				return err
			}
			// Keep the copies in ch consistent with what was saved.
			syncCopy(ch.New, f)
		}
		for i := range existing {
			f := &existing[i]
			if seen[f.ID] || f.Status != store.FindingOpen {
				continue
			}
			resolve(f, now, store.ResolutionFixed)
			if err := tx.SaveFinding(ctx, f); err != nil {
				return err
			}
			ch.Resolved = append(ch.Resolved, *f)
		}
		return nil
	})
	if err != nil {
		return Changes{}, err
	}
	return ch, nil
}

// ResolveUndeployed resolves open findings whose image is no longer used by
// any active workload. Call only after a successful discovery + workload sync.
func ResolveUndeployed(ctx context.Context, st store.Store, now time.Time) ([]store.Finding, error) {
	notDeployed := false
	var resolved []store.Finding
	err := st.Transaction(ctx, func(tx store.Store) error {
		for {
			page, _, err := tx.ListFindings(ctx, store.FindingFilter{
				Status: store.FindingOpen, Deployed: &notDeployed, Page: store.Page{Limit: 500},
			})
			if err != nil {
				return err
			}
			if len(page) == 0 {
				return nil
			}
			for i := range page {
				f := &page[i]
				resolve(f, now, store.ResolutionNotDeployed)
				if err := tx.SaveFinding(ctx, f); err != nil {
					return err
				}
				resolved = append(resolved, *f)
			}
		}
	})
	return resolved, err
}

func resolve(f *store.Finding, now time.Time, reason string) {
	f.Status = store.FindingResolved
	f.ResolvedAt = &now
	f.ResolutionReason = reason
}

func syncCopy(list []store.Finding, f *store.Finding) {
	for i := range list {
		if list[i].ID == f.ID {
			list[i] = *f
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
