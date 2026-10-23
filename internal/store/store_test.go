package store_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/l4r-s/krivy/internal/store"
	"github.com/l4r-s/krivy/internal/store/storetest"
)

var ctx = context.Background()

func ts(min int) time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

func ptr[T any](v T) *T { return &v }

func TestMigrationsIdempotent(t *testing.T) {
	storetest.ForEachTarget(t, func(t *testing.T, tg storetest.Target) {
		for i := 0; i < 3; i++ {
			st, err := store.Open(tg.Driver, tg.DSN)
			if err != nil {
				t.Fatalf("open #%d: %v", i, err)
			}
			if err := st.Ping(ctx); err != nil {
				t.Fatal(err)
			}
			// Migrate again on an already migrated handle.
			if err := store.Migrate(st.DB()); err != nil {
				t.Fatalf("re-migrate #%d: %v", i, err)
			}
			var rows []struct {
				Version int
				Name    string
			}
			if err := st.DB().Table("schema_migrations").Order("version").Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if len(rows) != store.SchemaVersion() || rows[len(rows)-1].Version != store.SchemaVersion() {
				t.Fatalf("schema_migrations = %+v, want versions up to %d", rows, store.SchemaVersion())
			}
			for _, m := range store.AllModels() {
				if !st.DB().Migrator().HasTable(m) {
					t.Fatalf("missing table for %T", m)
				}
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestOpenUnsupportedDriver(t *testing.T) {
	if _, err := store.Open("mysql", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestScanRuns(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		if _, err := st.GetScanRun(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetScanRun missing: %v", err)
		}
		if _, err := st.LatestScanRun(ctx, store.ScopeCluster, ""); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("LatestScanRun empty: %v", err)
		}
		runs := []store.ScanRun{
			{ID: "r1", Scope: store.ScopeCluster, Trigger: store.TriggerSchedule, Status: store.StatusSucceeded, CreatedAt: ts(1)},
			{ID: "r2", Scope: store.ScopeNamespace, Namespace: "prod", Trigger: store.TriggerAPI, Status: store.StatusFailed, CreatedAt: ts(2)},
			{ID: "r3", Scope: store.ScopeCluster, Trigger: store.TriggerAPI, Status: store.StatusRunning, CreatedAt: ts(3)},
			{ID: "r4", Scope: store.ScopeNamespace, Namespace: "staging", Trigger: store.TriggerMCP, Status: store.StatusPending, CreatedAt: ts(4)},
			{ID: "r5", Scope: store.ScopeNamespace, Namespace: "prod", Trigger: store.TriggerAPI, Status: store.StatusPending, CreatedAt: ts(5)},
		}
		for i := range runs {
			if err := st.CreateScanRun(ctx, &runs[i]); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.CreateScanRun(ctx, &store.ScanRun{ID: "r1", Scope: "cluster", Trigger: "api", Status: "pending"}); err == nil {
			t.Fatal("duplicate primary key accepted")
		}

		got, err := st.GetScanRun(ctx, "r2")
		if err != nil || got.Namespace != "prod" || got.Status != store.StatusFailed || !got.Terminal() {
			t.Fatalf("GetScanRun = %+v, %v", got, err)
		}
		got.Status = store.StatusSucceeded
		got.CompletedImages = 7
		got.FinishedAt = ptr(ts(10))
		if err := st.UpdateScanRun(ctx, got); err != nil {
			t.Fatal(err)
		}
		got, _ = st.GetScanRun(ctx, "r2")
		if got.CompletedImages != 7 || got.FinishedAt == nil || !got.FinishedAt.Equal(ts(10)) {
			t.Fatalf("update not persisted: %+v", got)
		}

		for _, tc := range []struct {
			name      string
			f         store.ScanRunFilter
			wantIDs   string
			wantTotal int64
		}{
			{"all newest first", store.ScanRunFilter{}, "r5,r4,r3,r2,r1", 5},
			{"page 1", store.ScanRunFilter{Page: store.Page{Limit: 2}}, "r5,r4", 5},
			{"page 2", store.ScanRunFilter{Page: store.Page{Limit: 2, Offset: 2}}, "r3,r2", 5},
			{"beyond end", store.ScanRunFilter{Page: store.Page{Limit: 2, Offset: 10}}, "", 5},
			{"negative offset", store.ScanRunFilter{Page: store.Page{Limit: 1, Offset: -3}}, "r5", 5},
			{"status", store.ScanRunFilter{Status: store.StatusPending}, "r5,r4", 2},
			{"scope", store.ScanRunFilter{Scope: store.ScopeCluster}, "r3,r1", 2},
			{"namespace", store.ScanRunFilter{Namespace: "prod"}, "r5,r2", 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out, total, err := st.ListScanRuns(ctx, tc.f)
				if err != nil {
					t.Fatal(err)
				}
				if ids := runIDs(out); ids != tc.wantIDs || total != tc.wantTotal {
					t.Fatalf("got %s (total %d), want %s (total %d)", ids, total, tc.wantIDs, tc.wantTotal)
				}
			})
		}

		active, err := st.ActiveScanRuns(ctx)
		if err != nil || runIDs(active) != "r3,r4,r5" {
			t.Fatalf("ActiveScanRuns = %s, %v", runIDs(active), err)
		}

		for _, tc := range []struct {
			scope, ns string
			statuses  []string
			want      string
		}{
			{store.ScopeCluster, "", nil, "r3"},
			{store.ScopeCluster, "", []string{store.StatusSucceeded}, "r1"},
			{store.ScopeNamespace, "prod", nil, "r5"},
			{store.ScopeNamespace, "prod", []string{store.StatusSucceeded, store.StatusPartial}, "r2"},
			{store.ScopeNamespace, "dev", nil, ""},
		} {
			r, err := st.LatestScanRun(ctx, tc.scope, tc.ns, tc.statuses...)
			if tc.want == "" {
				if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("LatestScanRun(%s,%s) err = %v", tc.scope, tc.ns, err)
				}
				continue
			}
			if err != nil || r.ID != tc.want {
				t.Errorf("LatestScanRun(%s,%s,%v) = %v, %v; want %s", tc.scope, tc.ns, tc.statuses, r, err, tc.want)
			}
		}
	})
}

func runIDs(rs []store.ScanRun) string {
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ",")
}

func TestPageNormalization(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		for i := 0; i < 60; i++ {
			if err := st.CreateScanRun(ctx, &store.ScanRun{ID: fmt.Sprintf("r%02d", i), Scope: "cluster", Trigger: "api", Status: "succeeded", CreatedAt: ts(i)}); err != nil {
				t.Fatal(err)
			}
		}
		out, total, err := st.ListScanRuns(ctx, store.ScanRunFilter{})
		if err != nil || len(out) != 50 || total != 60 {
			t.Fatalf("default limit: len=%d total=%d err=%v", len(out), total, err)
		}
		out, _, _ = st.ListScanRuns(ctx, store.ScanRunFilter{Page: store.Page{Limit: 10000}})
		if len(out) != 60 {
			t.Fatalf("large limit: len=%d", len(out))
		}
	})
}

func TestScanJobs(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		if err := st.CreateScanJobs(ctx, nil); err != nil {
			t.Fatal(err)
		}
		jobs := []store.ScanJob{
			{ID: "j2", ScanRunID: "run", ImageKey: "b", ImageRef: "b:1", Status: store.StatusPending, CreatedAt: ts(0)},
			{ID: "j1", ScanRunID: "run", ImageKey: "a", ImageRef: "a:1", Status: store.StatusPending, CreatedAt: ts(0)},
			{ID: "j3", ScanRunID: "other", ImageKey: "a", ImageRef: "a:1", Status: store.StatusPending, CreatedAt: ts(0)},
		}
		if err := st.CreateScanJobs(ctx, jobs); err != nil {
			t.Fatal(err)
		}
		dup := []store.ScanJob{{ID: "j4", ScanRunID: "run", ImageKey: "a", ImageRef: "a:1", Status: store.StatusPending}}
		if err := st.CreateScanJobs(ctx, dup); err == nil {
			t.Fatal("duplicate (run, image) accepted")
		}
		out, err := st.ListScanJobs(ctx, "run")
		if err != nil || len(out) != 2 || out[0].ImageKey != "a" || out[1].ImageKey != "b" {
			t.Fatalf("ListScanJobs = %+v, %v", out, err)
		}
		out[0].Status = store.StatusSucceeded
		out[0].Attempts = 2
		out[0].VulnCount = 3
		if err := st.UpdateScanJob(ctx, &out[0]); err != nil {
			t.Fatal(err)
		}
		out, _ = st.ListScanJobs(ctx, "run")
		if out[0].Status != store.StatusSucceeded || out[0].Attempts != 2 || out[0].VulnCount != 3 {
			t.Fatalf("update not persisted: %+v", out[0])
		}
	})
}

func TestImages(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		img := &store.Image{Key: "repo@sha256:1", Repository: "repo", Digest: "sha256:1", Ref: "repo@sha256:1",
			OS: "alpine 3.20", FirstSeenAt: ts(0), LastSeenAt: ts(0), Deployed: true}
		if err := st.UpsertImage(ctx, img); err != nil {
			t.Fatal(err)
		}
		// Upsert again: first_seen_at and os must be preserved, others updated.
		if err := st.UpsertImage(ctx, &store.Image{Key: "repo@sha256:1", Repository: "repo", Digest: "sha256:1",
			Ref: "repo:tag", FirstSeenAt: ts(50), LastSeenAt: ts(50), Deployed: false}); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetImage(ctx, "repo@sha256:1")
		if err != nil {
			t.Fatal(err)
		}
		if !got.FirstSeenAt.Equal(ts(0)) || !got.LastSeenAt.Equal(ts(50)) || got.Ref != "repo:tag" || got.Deployed || got.OS != "alpine 3.20" {
			t.Fatalf("upsert result: %+v", got)
		}
		if _, err := st.GetImage(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetImage missing: %v", err)
		}
		_ = st.UpsertImage(ctx, &store.Image{Key: "a", Ref: "a"})
		all, err := st.ListImages(ctx, nil)
		if err != nil || len(all) != 2 || all[0].Key != "a" {
			t.Fatalf("ListImages(nil) = %+v, %v", all, err)
		}
		none, err := st.ListImages(ctx, []string{})
		if err != nil || len(none) != 0 {
			t.Fatalf("ListImages(empty) = %+v, %v", none, err)
		}
		some, _ := st.ListImages(ctx, []string{"a", "zzz"})
		if len(some) != 1 {
			t.Fatalf("ListImages(keys) = %+v", some)
		}
	})
}

// Fixture: "shared" image runs in production and staging, "prodonly" and
// "stagingonly" in one namespace each.
func seedWorkloads(t *testing.T, st store.Store) {
	t.Helper()
	for _, k := range []string{"shared", "prodonly", "stagingonly"} {
		if err := st.UpsertImage(ctx, &store.Image{Key: k, Repository: k, Ref: k, FirstSeenAt: ts(0), LastSeenAt: ts(0), Deployed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SyncWorkloads(ctx, "", []store.Workload{
		{ImageKey: "shared", Namespace: "production", Kind: "Deployment", Name: "api", Container: "app"},
		{ImageKey: "prodonly", Namespace: "production", Kind: "Deployment", Name: "db", Container: "pg"},
		{ImageKey: "shared", Namespace: "staging", Kind: "Deployment", Name: "api", Container: "app"},
		{ImageKey: "stagingonly", Namespace: "staging", Kind: "CronJob", Name: "job", Container: "c"},
	}, ts(0)); err != nil {
		t.Fatal(err)
	}
}

func deployedState(t *testing.T, st store.Store) map[string]bool {
	t.Helper()
	imgs, err := st.ListImages(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, i := range imgs {
		out[i.Key] = i.Deployed
	}
	return out
}

func activeWorkloads(t *testing.T, st store.Store) string {
	t.Helper()
	ws, err := st.ListWorkloads(ctx, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, w := range ws {
		out = append(out, w.Namespace+"/"+w.Name+"/"+w.ImageKey)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestSyncWorkloadsNamespaceIsolation(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		seedWorkloads(t, st)
		if got := activeWorkloads(t, st); got != "production/api/shared,production/db/prodonly,staging/api/shared,staging/job/stagingonly" {
			t.Fatalf("initial active = %s", got)
		}

		// Staging scan sees only the shared image: stagingonly goes away but
		// production must be untouched.
		if err := st.SyncWorkloads(ctx, "staging", []store.Workload{
			{ImageKey: "shared", Namespace: "staging", Kind: "Deployment", Name: "api", Container: "app"},
		}, ts(10)); err != nil {
			t.Fatal(err)
		}
		if got := activeWorkloads(t, st); got != "production/api/shared,production/db/prodonly,staging/api/shared" {
			t.Fatalf("after staging sync active = %s", got)
		}
		if d := deployedState(t, st); !d["shared"] || !d["prodonly"] || d["stagingonly"] {
			t.Fatalf("deployed after staging sync = %v", d)
		}

		// Staging becomes empty: shared image stays deployed through production.
		if err := st.SyncWorkloads(ctx, "staging", nil, ts(20)); err != nil {
			t.Fatal(err)
		}
		if d := deployedState(t, st); !d["shared"] || !d["prodonly"] || d["stagingonly"] {
			t.Fatalf("deployed after empty staging sync = %v", d)
		}
		if got := activeWorkloads(t, st); got != "production/api/shared,production/db/prodonly" {
			t.Fatalf("active = %s", got)
		}

		// Cluster-wide sync without the shared image undeploys it.
		if err := st.SyncWorkloads(ctx, "", []store.Workload{
			{ImageKey: "prodonly", Namespace: "production", Kind: "Deployment", Name: "db", Container: "pg"},
		}, ts(30)); err != nil {
			t.Fatal(err)
		}
		if d := deployedState(t, st); d["shared"] || !d["prodonly"] || d["stagingonly"] {
			t.Fatalf("deployed after cluster sync = %v", d)
		}

		// Reactivation keeps first-seen and updates last-seen.
		if err := st.SyncWorkloads(ctx, "staging", []store.Workload{
			{ImageKey: "stagingonly", Namespace: "staging", Kind: "CronJob", Name: "job", Container: "c"},
		}, ts(40)); err != nil {
			t.Fatal(err)
		}
		ws, err := st.ListWorkloads(ctx, []string{"stagingonly"}, true)
		if err != nil || len(ws) != 1 {
			t.Fatalf("ListWorkloads = %+v, %v", ws, err)
		}
		if !ws[0].FirstSeenAt.Equal(ts(0)) || !ws[0].LastSeenAt.Equal(ts(40)) {
			t.Fatalf("timestamps = first %v last %v", ws[0].FirstSeenAt, ws[0].LastSeenAt)
		}
		if d := deployedState(t, st); !d["stagingonly"] || !d["prodonly"] {
			t.Fatalf("deployed after reactivation = %v", d)
		}
		all, _ := st.ListWorkloads(ctx, nil, false)
		if len(all) != 4 {
			t.Fatalf("inactive workloads must be kept, got %d", len(all))
		}
		if none, _ := st.ListWorkloads(ctx, []string{}, false); len(none) != 0 {
			t.Fatalf("ListWorkloads(empty) = %v", none)
		}
	})
}

func seedFindings(t *testing.T, st store.Store) {
	t.Helper()
	seedWorkloads(t, st)
	// An image no longer deployed anywhere.
	if err := st.UpsertImage(ctx, &store.Image{Key: "gone", Ref: "gone", Deployed: false}); err != nil {
		t.Fatal(err)
	}
	fs := []store.Finding{
		{ID: "f1", ImageKey: "shared", VulnerabilityID: "CVE-1", PkgName: "openssl", Severity: "CRITICAL", Status: store.FindingOpen, FirstSeenAt: ts(1)},
		{ID: "f2", ImageKey: "prodonly", VulnerabilityID: "CVE-2", PkgName: "libc", Severity: "HIGH", Status: store.FindingOpen, FirstSeenAt: ts(2), AcknowledgedAt: ptr(ts(3)), AckBy: "token:x"},
		{ID: "f3", ImageKey: "stagingonly", VulnerabilityID: "CVE-1", PkgName: "openssl", Severity: "CRITICAL", Status: store.FindingOpen, FirstSeenAt: ts(3)},
		{ID: "f4", ImageKey: "stagingonly", VulnerabilityID: "CVE-3", PkgName: "zlib", Severity: "CRITICAL", Status: store.FindingResolved, FirstSeenAt: ts(4), ResolvedAt: ptr(ts(5)), ResolutionReason: store.ResolutionFixed},
		{ID: "f5", ImageKey: "gone", VulnerabilityID: "CVE-4", PkgName: "curl", Severity: "CRITICAL", Status: store.FindingOpen, FirstSeenAt: ts(5)},
	}
	for i := range fs {
		if err := st.SaveFinding(ctx, &fs[i]); err != nil {
			t.Fatal(err)
		}
	}
}

func findingIDs(fs []store.Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return strings.Join(ids, ",")
}

func TestFindingFilters(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		seedFindings(t, st)
		for _, tc := range []struct {
			name      string
			f         store.FindingFilter
			want      string
			wantTotal int64
		}{
			{"all newest first", store.FindingFilter{}, "f5,f4,f3,f2,f1", 5},
			{"open", store.FindingFilter{Status: store.FindingOpen}, "f5,f3,f2,f1", 4},
			{"resolved", store.FindingFilter{Status: store.FindingResolved}, "f4", 1},
			{"severity case-insensitive", store.FindingFilter{Severity: "high"}, "f2", 1},
			{"image", store.FindingFilter{ImageKey: "stagingonly"}, "f4,f3", 2},
			{"vuln", store.FindingFilter{VulnerabilityID: "CVE-1"}, "f3,f1", 2},
			{"namespace production", store.FindingFilter{Namespace: "production"}, "f2,f1", 2},
			{"namespace staging", store.FindingFilter{Namespace: "staging"}, "f4,f3,f1", 3},
			{"namespace unknown", store.FindingFilter{Namespace: "dev"}, "", 0},
			{"acknowledged", store.FindingFilter{Acknowledged: ptr(true)}, "f2", 1},
			{"unacknowledged open", store.FindingFilter{Status: store.FindingOpen, Acknowledged: ptr(false)}, "f5,f3,f1", 3},
			{"deployed", store.FindingFilter{Deployed: ptr(true)}, "f4,f3,f2,f1", 4},
			{"not deployed", store.FindingFilter{Deployed: ptr(false)}, "f5", 1},
			{"combined", store.FindingFilter{Status: store.FindingOpen, Severity: "CRITICAL", Namespace: "staging"}, "f3,f1", 2},
			{"paginated", store.FindingFilter{Page: store.Page{Limit: 2, Offset: 1}}, "f4,f3", 5},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out, total, err := st.ListFindings(ctx, tc.f)
				if err != nil {
					t.Fatal(err)
				}
				if got := findingIDs(out); got != tc.want || total != tc.wantTotal {
					t.Fatalf("got %s (total %d), want %s (total %d)", got, total, tc.want, tc.wantTotal)
				}
			})
		}

		// Namespace filter follows workload activity.
		if err := st.SyncWorkloads(ctx, "staging", nil, ts(60)); err != nil {
			t.Fatal(err)
		}
		out, _, _ := st.ListFindings(ctx, store.FindingFilter{Namespace: "staging"})
		if len(out) != 0 {
			t.Fatalf("staging after undeploy = %s", findingIDs(out))
		}

		byImg, err := st.ListFindingsByImage(ctx, "stagingonly")
		if err != nil || findingIDs(byImg) != "f3,f4" {
			t.Fatalf("ListFindingsByImage = %s, %v", findingIDs(byImg), err)
		}
		f, err := st.GetFinding(ctx, "f2")
		if err != nil || f.AckBy != "token:x" || f.AcknowledgedAt == nil {
			t.Fatalf("GetFinding = %+v, %v", f, err)
		}
		if _, err := st.GetFinding(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetFinding missing: %v", err)
		}
	})
}

func TestSilences(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		now := ts(100)
		for _, s := range []store.Silence{
			{ID: "active", Kind: store.SilenceImage, Target: "x", CreatedAt: ts(1)},
			{ID: "future", Kind: store.SilenceImage, Target: "x", CreatedAt: ts(2), ExpiresAt: ptr(ts(200))},
			{ID: "expired", Kind: store.SilenceImage, Target: "x", CreatedAt: ts(3), ExpiresAt: ptr(ts(50))},
			{ID: "revoked", Kind: store.SilenceImage, Target: "x", CreatedAt: ts(4), RevokedAt: ptr(ts(5))},
		} {
			s := s
			if err := st.CreateSilence(ctx, &s); err != nil {
				t.Fatal(err)
			}
			if s.ActiveAt(now) != (s.ID == "active" || s.ID == "future") {
				t.Fatalf("ActiveAt(%s) wrong", s.ID)
			}
		}
		all, err := st.ListSilences(ctx, nil)
		if err != nil || len(all) != 4 || all[0].ID != "revoked" {
			t.Fatalf("ListSilences(nil) = %+v, %v", all, err)
		}
		active, err := st.ListSilences(ctx, &now)
		if err != nil || len(active) != 2 || active[0].ID != "future" || active[1].ID != "active" {
			t.Fatalf("ListSilences(now) = %+v, %v", active, err)
		}
		s, err := st.GetSilence(ctx, "active")
		if err != nil {
			t.Fatal(err)
		}
		s.RevokedAt, s.RevokedBy = ptr(ts(99)), "token:a"
		if err := st.UpdateSilence(ctx, s); err != nil {
			t.Fatal(err)
		}
		active, _ = st.ListSilences(ctx, &now)
		if len(active) != 1 {
			t.Fatalf("after revoke = %+v", active)
		}
		if _, err := st.GetSilence(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetSilence missing: %v", err)
		}
	})
}

func TestDeliveries(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		d := &store.NotificationDelivery{ID: "d1", Destination: "hook", Event: "new_critical", DedupKey: "k1", Status: store.DeliveryPending, CreatedAt: ts(1)}
		if err := st.CreateDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
		err := st.CreateDelivery(ctx, &store.NotificationDelivery{ID: "d2", Destination: "hook", Event: "new_critical", DedupKey: "k1", Status: store.DeliveryPending})
		if !errors.Is(err, store.ErrDuplicate) {
			t.Fatalf("duplicate dedup key: err = %v, want ErrDuplicate", err)
		}
		// The failed insert must not poison later writes.
		if err := st.CreateDelivery(ctx, &store.NotificationDelivery{ID: "d3", Destination: "hook", Event: "resolved", DedupKey: "k3", Status: store.DeliveryFailed, CreatedAt: ts(2)}); err != nil {
			t.Fatal(err)
		}
		d.Status, d.Attempts, d.ResponseCode = store.DeliveryDelivered, 1, 204
		if err := st.UpdateDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			status string
			limit  int
			want   int
		}{
			{"", 0, 2},
			{"", 1, 1},
			{store.DeliveryDelivered, 10, 1},
			{store.DeliveryPending, 10, 0},
		} {
			out, err := st.ListDeliveries(ctx, tc.status, tc.limit)
			if err != nil || len(out) != tc.want {
				t.Errorf("ListDeliveries(%q,%d) = %d, %v; want %d", tc.status, tc.limit, len(out), err, tc.want)
			}
		}
	})
}

func TestSummary(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		empty, err := st.Summary(ctx)
		if err != nil || empty.OpenFindings != 0 || empty.LastScan != nil || empty.LastSuccessfulScan != nil {
			t.Fatalf("empty summary = %+v, %v", empty, err)
		}
		seedFindings(t, st)
		now := time.Now().UTC()
		for _, s := range []store.Silence{
			{ID: "s1", Kind: "image", Target: "x", CreatedAt: now},
			{ID: "s2", Kind: "image", Target: "x", CreatedAt: now, ExpiresAt: ptr(now.Add(-time.Hour))},
			{ID: "s3", Kind: "image", Target: "x", CreatedAt: now, RevokedAt: ptr(now)},
		} {
			s := s
			if err := st.CreateSilence(ctx, &s); err != nil {
				t.Fatal(err)
			}
		}
		for _, r := range []store.ScanRun{
			{ID: "ok", Scope: "cluster", Trigger: "api", Status: store.StatusSucceeded, CreatedAt: ts(1)},
			{ID: "bad", Scope: "cluster", Trigger: "api", Status: store.StatusFailed, CreatedAt: ts(2)},
		} {
			r := r
			if err := st.CreateScanRun(ctx, &r); err != nil {
				t.Fatal(err)
			}
		}
		s, err := st.Summary(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, ch := range []struct {
			name      string
			got, want int64
		}{
			{"open", s.OpenFindings, 4},
			{"open unacked", s.OpenUnacknowledged, 3},
			{"critical", s.OpenBySeverity["CRITICAL"], 3},
			{"high", s.OpenBySeverity["HIGH"], 1},
			{"affected images", s.AffectedImages, 4},
			{"deployed images", s.DeployedImages, 3},
			{"active silences", s.ActiveSilences, 1},
			{"ns production", s.OpenByNamespace["production"], 2},
			{"ns staging", s.OpenByNamespace["staging"], 2},
		} {
			if ch.got != ch.want {
				t.Errorf("%s = %d, want %d", ch.name, ch.got, ch.want)
			}
		}
		if len(s.OpenByNamespace) != 2 {
			t.Errorf("OpenByNamespace = %v", s.OpenByNamespace)
		}
		if s.LastScan == nil || s.LastScan.ID != "bad" || s.LastSuccessfulScan == nil || s.LastSuccessfulScan.ID != "ok" {
			t.Errorf("last scans = %+v / %+v", s.LastScan, s.LastSuccessfulScan)
		}
	})
}

func TestTransaction(t *testing.T) {
	storetest.ForEachDriver(t, func(t *testing.T, st *store.GormStore) {
		boom := errors.New("boom")
		err := st.Transaction(ctx, func(tx store.Store) error {
			if err := tx.SaveFinding(ctx, &store.Finding{ID: "rolled-back", ImageKey: "i", VulnerabilityID: "v", PkgName: "p", Status: "open"}); err != nil {
				return err
			}
			if err := tx.CreateScanRun(ctx, &store.ScanRun{ID: "rb", Scope: "cluster", Trigger: "api", Status: "pending"}); err != nil {
				return err
			}
			// Nested transactional helper inside a transaction.
			if err := tx.SyncWorkloads(ctx, "ns", []store.Workload{{ImageKey: "i", Namespace: "ns", Kind: "Pod", Name: "p", Container: "c"}}, ts(0)); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if _, err := st.GetFinding(ctx, "rolled-back"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("finding survived rollback: %v", err)
		}
		if _, err := st.GetScanRun(ctx, "rb"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("run survived rollback: %v", err)
		}
		if ws, _ := st.ListWorkloads(ctx, nil, false); len(ws) != 0 {
			t.Fatalf("workloads survived rollback: %+v", ws)
		}

		if err := st.Transaction(ctx, func(tx store.Store) error {
			return tx.SaveFinding(ctx, &store.Finding{ID: "committed", ImageKey: "i", VulnerabilityID: "v", PkgName: "p", Status: "open"})
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetFinding(ctx, "committed"); err != nil {
			t.Fatalf("committed finding missing: %v", err)
		}
	})
}
