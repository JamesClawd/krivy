package findings_test

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/l4r-s/krivy/internal/findings"
	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/store"
	"github.com/l4r-s/krivy/internal/store/storetest"
)

var ctx = context.Background()

func ts(min int) time.Time {
	return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func ptr[T any](v T) *T { return &v }

func vuln(id, pkg, ver, sev string) scanner.Vulnerability {
	return scanner.Vulnerability{VulnerabilityID: id, PkgName: pkg, InstalledVersion: ver, Severity: sev, FixedVersion: ver + "-fix", Title: id + " title"}
}

func vulnIDs(fs []store.Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.VulnerabilityID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

func TestIDStability(t *testing.T) {
	a := findings.ID("img", "CVE-1", "openssl", "", "1.0")
	if a != findings.ID("img", "CVE-1", "openssl", "", "1.0") {
		t.Fatal("ID not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("ID length %d", len(a))
	}
	for _, other := range []string{
		findings.ID("img2", "CVE-1", "openssl", "", "1.0"),
		findings.ID("img", "CVE-2", "openssl", "", "1.0"),
		findings.ID("img", "CVE-1", "libssl", "", "1.0"),
		findings.ID("img", "CVE-1", "openssl", "/usr/lib", "1.0"),
		findings.ID("img", "CVE-1", "openssl", "", "1.1"),
		// Separator prevents concatenation collisions.
		findings.ID("im", "gCVE-1", "openssl", "", "1.0"),
	} {
		if other == a {
			t.Fatal("distinct inputs produced the same ID")
		}
	}
}

func TestReconcileLifecycle(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		const img = "repo@sha256:a"
		// 1. New: duplicates within one report are deduplicated.
		ch, err := findings.ReconcileImage(ctx, st, "run1", img, []scanner.Vulnerability{
			vuln("CVE-1", "openssl", "1.0", "critical"),
			vuln("CVE-1", "openssl", "1.0", "critical"),
			vuln("CVE-2", "zlib", "1.2", "HIGH"),
		}, ts(0))
		if err != nil {
			t.Fatal(err)
		}
		if len(ch.New) != 2 || len(ch.Resolved) != 0 {
			t.Fatalf("first reconcile: %d new, %d resolved", len(ch.New), len(ch.Resolved))
		}
		for _, f := range ch.New {
			if f.Severity == "" || f.LastScanRunID != "run1" || f.Status != store.FindingOpen || f.FixedVersion == "" {
				t.Fatalf("change copy not synced with saved finding: %+v", f)
			}
		}
		id1 := findings.ID(img, "CVE-1", "openssl", "", "1.0")
		f1, err := st.GetFinding(ctx, id1)
		if err != nil {
			t.Fatal(err)
		}
		if f1.Severity != "CRITICAL" || !f1.FirstSeenAt.Equal(ts(0)) || f1.Title != "CVE-1 title" {
			t.Fatalf("stored finding: %+v", f1)
		}

		// 2. Refresh: same vulns, nothing new, advisory data updated.
		v1 := vuln("CVE-1", "openssl", "1.0", "CRITICAL")
		v1.FixedVersion = "1.0.1"
		ch, err = findings.ReconcileImage(ctx, st, "run2", img, []scanner.Vulnerability{v1, vuln("CVE-2", "zlib", "1.2", "HIGH")}, ts(10))
		if err != nil || len(ch.New) != 0 || len(ch.Resolved) != 0 {
			t.Fatalf("refresh: %+v, %v", ch, err)
		}
		f1, _ = st.GetFinding(ctx, id1)
		if f1.FixedVersion != "1.0.1" || !f1.LastSeenAt.Equal(ts(10)) || !f1.FirstSeenAt.Equal(ts(0)) || f1.LastScanRunID != "run2" {
			t.Fatalf("refresh not applied: %+v", f1)
		}

		// Acknowledge CVE-1.
		f1.AcknowledgedAt, f1.AckBy, f1.AckReason = ptr(ts(11)), "token:admin", "accepted"
		if err := st.SaveFinding(ctx, f1); err != nil {
			t.Fatal(err)
		}

		// 3. Resolve: CVE-1 disappears → resolved as fixed.
		ch, err = findings.ReconcileImage(ctx, st, "run3", img, []scanner.Vulnerability{vuln("CVE-2", "zlib", "1.2", "HIGH")}, ts(20))
		if err != nil || len(ch.New) != 0 || vulnIDs(ch.Resolved) != "CVE-1" {
			t.Fatalf("resolve: %+v, %v", ch, err)
		}
		f1, _ = st.GetFinding(ctx, id1)
		if f1.Status != store.FindingResolved || f1.ResolutionReason != store.ResolutionFixed || f1.ResolvedAt == nil || !f1.ResolvedAt.Equal(ts(20)) {
			t.Fatalf("not resolved: %+v", f1)
		}
		// Resolving again is a no-op.
		ch, _ = findings.ReconcileImage(ctx, st, "run4", img, []scanner.Vulnerability{vuln("CVE-2", "zlib", "1.2", "HIGH")}, ts(25))
		if len(ch.Resolved) != 0 || len(ch.New) != 0 {
			t.Fatalf("second resolve not a no-op: %+v", ch)
		}

		// 4. Reopen: comes back, ack cleared, same ID.
		ch, err = findings.ReconcileImage(ctx, st, "run5", img, []scanner.Vulnerability{
			vuln("CVE-1", "openssl", "1.0", "CRITICAL"), vuln("CVE-2", "zlib", "1.2", "HIGH"),
		}, ts(30))
		if err != nil || vulnIDs(ch.New) != "CVE-1" || len(ch.Resolved) != 0 {
			t.Fatalf("reopen: %+v, %v", ch, err)
		}
		if ch.New[0].ID != id1 || ch.New[0].AcknowledgedAt != nil {
			t.Fatalf("reopen change: %+v", ch.New[0])
		}
		f1, _ = st.GetFinding(ctx, id1)
		if f1.Status != store.FindingOpen || f1.AcknowledgedAt != nil || f1.AckBy != "" || f1.AckReason != "" ||
			f1.ResolvedAt != nil || f1.ResolutionReason != "" || f1.ReopenedAt == nil || !f1.ReopenedAt.Equal(ts(30)) ||
			!f1.FirstSeenAt.Equal(ts(0)) {
			t.Fatalf("reopened finding: %+v", f1)
		}

		// 5. Clean scan resolves everything for this image.
		ch, err = findings.ReconcileImage(ctx, st, "run6", img, nil, ts(40))
		if err != nil || vulnIDs(ch.Resolved) != "CVE-1,CVE-2" {
			t.Fatalf("clean scan: %+v, %v", ch, err)
		}
	})
}

func TestReconcileOnlyTouchesItsImage(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		if _, err := findings.ReconcileImage(ctx, st, "r", "imgA", []scanner.Vulnerability{vuln("CVE-1", "p", "1", "CRITICAL")}, ts(0)); err != nil {
			t.Fatal(err)
		}
		if _, err := findings.ReconcileImage(ctx, st, "r", "imgB", []scanner.Vulnerability{vuln("CVE-1", "p", "1", "CRITICAL")}, ts(0)); err != nil {
			t.Fatal(err)
		}
		ch, err := findings.ReconcileImage(ctx, st, "r2", "imgB", nil, ts(1))
		if err != nil || len(ch.Resolved) != 1 || ch.Resolved[0].ImageKey != "imgB" {
			t.Fatalf("%+v, %v", ch, err)
		}
		a, _ := st.ListFindingsByImage(ctx, "imgA")
		if len(a) != 1 || a[0].Status != store.FindingOpen {
			t.Fatalf("imgA touched: %+v", a)
		}
		// Same CVE in two images has different IDs.
		b, _ := st.ListFindingsByImage(ctx, "imgB")
		if a[0].ID == b[0].ID {
			t.Fatal("finding IDs must differ per image")
		}
	})
}

func TestReconcileTruncatesLongFields(t *testing.T) {
	st := storetest.SQLite(t)
	v := vuln("CVE-9", "p", "1", "LOW")
	v.Title = strings.Repeat("x", 3000)
	if _, err := findings.ReconcileImage(ctx, st, "r", "img", []scanner.Vulnerability{v}, ts(0)); err != nil {
		t.Fatal(err)
	}
	fs, _ := st.ListFindingsByImage(ctx, "img")
	if len(fs[0].Title) != 1024 {
		t.Fatalf("title length %d", len(fs[0].Title))
	}
}

func TestResolveUndeployed(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		for _, k := range []string{"kept", "gone", "shared"} {
			if err := st.UpsertImage(ctx, &store.Image{Key: k, Ref: k, Deployed: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := findings.ReconcileImage(ctx, st, "r", k, []scanner.Vulnerability{
				vuln("CVE-1", "p", "1", "CRITICAL"), vuln("CVE-2", "q", "1", "HIGH"),
			}, ts(0)); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.SyncWorkloads(ctx, "", []store.Workload{
			{ImageKey: "kept", Namespace: "a", Kind: "Pod", Name: "p", Container: "c"},
			{ImageKey: "gone", Namespace: "b", Kind: "Pod", Name: "p", Container: "c"},
			{ImageKey: "shared", Namespace: "a", Kind: "Pod", Name: "s", Container: "c"},
			{ImageKey: "shared", Namespace: "b", Kind: "Pod", Name: "s", Container: "c"},
		}, ts(0)); err != nil {
			t.Fatal(err)
		}
		if res, err := findings.ResolveUndeployed(ctx, st, ts(1)); err != nil || len(res) != 0 {
			t.Fatalf("nothing should resolve: %+v, %v", res, err)
		}
		// Namespace b disappears: "gone" is undeployed, "shared" stays via a.
		if err := st.SyncWorkloads(ctx, "b", nil, ts(2)); err != nil {
			t.Fatal(err)
		}
		res, err := findings.ResolveUndeployed(ctx, st, ts(3))
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 {
			t.Fatalf("resolved %d, want 2", len(res))
		}
		for _, f := range res {
			if f.ImageKey != "gone" || f.ResolutionReason != store.ResolutionNotDeployed || f.Status != store.FindingResolved {
				t.Fatalf("unexpected resolution: %+v", f)
			}
		}
		for _, k := range []string{"kept", "shared"} {
			fs, _ := st.ListFindingsByImage(ctx, k)
			for _, f := range fs {
				if f.Status != store.FindingOpen {
					t.Fatalf("%s finding resolved: %+v", k, f)
				}
			}
		}
		// Idempotent.
		if res, _ := findings.ResolveUndeployed(ctx, st, ts(4)); len(res) != 0 {
			t.Fatalf("second pass resolved %d", len(res))
		}
	})
}

func TestResolveUndeployedManyPages(t *testing.T) {
	st := storetest.SQLite(t)
	if err := st.UpsertImage(ctx, &store.Image{Key: "gone", Ref: "gone", Deployed: false}); err != nil {
		t.Fatal(err)
	}
	var vs []scanner.Vulnerability
	for i := 0; i < 1203; i++ {
		vs = append(vs, vuln("CVE-"+strings.Repeat("1", 1)+string(rune('a'+i%26)), "p", string(rune('A'+i/26)), "LOW"))
	}
	ch, err := findings.ReconcileImage(ctx, st, "r", "gone", vs, ts(0))
	if err != nil {
		t.Fatal(err)
	}
	res, err := findings.ResolveUndeployed(ctx, st, ts(1))
	if err != nil || len(res) != len(ch.New) {
		t.Fatalf("resolved %d of %d, err %v", len(res), len(ch.New), err)
	}
}

func TestChangesAdd(t *testing.T) {
	var c findings.Changes
	c.Add(findings.Changes{New: []store.Finding{{ID: "a"}}, Resolved: []store.Finding{{ID: "b"}}})
	c.Add(findings.Changes{New: []store.Finding{{ID: "c"}}})
	if len(c.New) != 2 || len(c.Resolved) != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestPolicy(t *testing.T) {
	now := ts(100)
	f := &store.Finding{ID: "fid", ImageKey: "docker.io/library/nginx@sha256:abc", VulnerabilityID: "CVE-2024-1", Severity: "CRITICAL"}
	const repo = "docker.io/library/nginx"
	sil := func(id, kind, target string) store.Silence {
		return store.Silence{ID: id, Kind: kind, Target: target, CreatedAt: ts(0)}
	}
	expired := sil("exp", store.SilenceVulnerability, "CVE-2024-1")
	expired.ExpiresAt = ptr(ts(50))
	revoked := sil("rev", store.SilenceFinding, "fid")
	revoked.RevokedAt = ptr(ts(60))
	future := sil("fut", store.SilenceFinding, "fid")
	future.ExpiresAt = ptr(ts(200))

	for _, tc := range []struct {
		name       string
		silences   []store.Silence
		repo       string
		namespaces []string
		acked      bool
		wantBy     string
		alertNew   bool
		alertRes   bool
	}{
		{"no silences alerts", nil, repo, []string{"prod"}, false, "", true, true},
		{"acked does not alert new", nil, repo, []string{"prod"}, true, "", false, true},
		{"finding silence", []store.Silence{sil("s", store.SilenceFinding, "fid")}, repo, nil, false, "s", false, false},
		{"other finding", []store.Silence{sil("s", store.SilenceFinding, "other")}, repo, nil, false, "", true, true},
		{"image exact key", []store.Silence{sil("s", store.SilenceImage, f.ImageKey)}, repo, nil, false, "s", false, false},
		{"image repository", []store.Silence{sil("s", store.SilenceImage, repo)}, repo, nil, false, "s", false, false},
		{"image repository unknown repo", []store.Silence{sil("s", store.SilenceImage, repo)}, "", nil, false, "", true, true},
		{"image other digest", []store.Silence{sil("s", store.SilenceImage, repo+"@sha256:def")}, repo, nil, false, "", true, true},
		{"image other repo", []store.Silence{sil("s", store.SilenceImage, "docker.io/library/redis")}, repo, nil, false, "", true, true},
		{"vulnerability", []store.Silence{sil("s", store.SilenceVulnerability, "CVE-2024-1")}, repo, nil, false, "s", false, false},
		{"vulnerability case-insensitive", []store.Silence{sil("s", store.SilenceVulnerability, "cve-2024-1")}, repo, nil, false, "s", false, false},
		{"other vulnerability", []store.Silence{sil("s", store.SilenceVulnerability, "CVE-2024-2")}, repo, nil, false, "", true, true},
		{"expired ignored", []store.Silence{expired}, repo, nil, false, "", true, true},
		{"revoked ignored", []store.Silence{revoked}, repo, nil, false, "", true, true},
		{"future expiry active", []store.Silence{future}, repo, nil, false, "fut", false, false},
		{"namespace single", []store.Silence{sil("n", store.SilenceNamespace, "prod")}, repo, []string{"prod"}, false, "n", false, false},
		{"namespace shared image partially silenced", []store.Silence{sil("n", store.SilenceNamespace, "prod")}, repo, []string{"prod", "staging"}, false, "", true, true},
		{"namespace shared image fully silenced", []store.Silence{sil("n1", store.SilenceNamespace, "prod"), sil("n2", store.SilenceNamespace, "staging")}, repo, []string{"prod", "staging"}, false, "n1,n2", false, false},
		{"duplicate namespace silences dedupe", []store.Silence{sil("n1", store.SilenceNamespace, "prod")}, repo, []string{"prod", "prod"}, false, "n1", false, false},
		{"namespace silence, image undeployed", []store.Silence{sil("n", store.SilenceNamespace, "prod")}, repo, nil, false, "", true, true},
		{"namespace silence other namespace", []store.Silence{sil("n", store.SilenceNamespace, "dev")}, repo, []string{"prod"}, false, "", true, true},
		{"direct silence wins over partial namespace", []store.Silence{sil("n", store.SilenceNamespace, "prod"), sil("v", store.SilenceVulnerability, "CVE-2024-1")}, repo, []string{"prod", "staging"}, false, "v", false, false},
		{"expired namespace silence ignored", []store.Silence{func() store.Silence {
			s := sil("n", store.SilenceNamespace, "prod")
			s.ExpiresAt = ptr(ts(1))
			return s
		}()}, repo, []string{"prod"}, false, "", true, true},
		{"multiple direct", []store.Silence{sil("a", store.SilenceFinding, "fid"), sil("b", store.SilenceVulnerability, "CVE-2024-1")}, repo, nil, false, "a,b", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ff := *f
			if tc.acked {
				ff.AcknowledgedAt = ptr(ts(5))
			}
			p := findings.NewPolicy(tc.silences, now)
			by := p.SilencedBy(&ff, tc.repo, tc.namespaces)
			sort.Strings(by)
			if got := strings.Join(by, ","); got != tc.wantBy {
				t.Errorf("SilencedBy = %q, want %q", got, tc.wantBy)
			}
			if got := p.ShouldAlertNew(&ff, tc.repo, tc.namespaces); got != tc.alertNew {
				t.Errorf("ShouldAlertNew = %v, want %v", got, tc.alertNew)
			}
			if got := p.ShouldAlertResolved(&ff, tc.repo, tc.namespaces); got != tc.alertRes {
				t.Errorf("ShouldAlertResolved = %v, want %v", got, tc.alertRes)
			}
		})
	}
}

func TestMatchesIgnoresNamespaceKind(t *testing.T) {
	f := &store.Finding{ID: "x", ImageKey: "k", VulnerabilityID: "CVE-1"}
	if findings.Matches(&store.Silence{Kind: store.SilenceNamespace, Target: "prod"}, f, "", []string{"prod"}) {
		t.Fatal("namespace silences are handled by SilencedBy, not Matches")
	}
	if findings.Matches(&store.Silence{Kind: "bogus", Target: "x"}, f, "", nil) {
		t.Fatal("unknown kind matched")
	}
}
