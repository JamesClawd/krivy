//go:build integration

// Package integration exercises Krivy against the k3d dev cluster created by
// `make dev-cluster dev-seed`. Run with `make test-integration`.
//
// Environment:
//
//	KRIVY_INTEGRATION=1            required, guards against accidental runs
//	KRIVY_KUBECONFIG               kubeconfig path (default <repo>/.dev/kubeconfig)
//	KRIVY_INTEGRATION_REAL_TRIVY=1 also run a real Trivy scan (downloads the
//	                               vulnerability DB: ~1 GiB RAM, network)
package integration

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/discovery"
	"github.com/l4r-s/krivy/internal/kube"
	"github.com/l4r-s/krivy/internal/notify"
	"github.com/l4r-s/krivy/internal/orchestrator"
	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/store"
)

const (
	devContext   = "k3d-krivy-dev"
	jobNamespace = "krivy-system"
	stubImage    = "busybox:1.36.1"
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// client connects only to the dedicated dev context, never the default one.
func client(t *testing.T) kubernetes.Interface {
	t.Helper()
	if os.Getenv("KRIVY_INTEGRATION") != "1" {
		t.Skip("set KRIVY_INTEGRATION=1 (use make test-integration)")
	}
	path := os.Getenv("KRIVY_KUBECONFIG")
	if path == "" {
		path = filepath.Join(repoRoot(), ".dev", "kubeconfig")
	}
	cs, name, err := kube.NewClient(kube.Options{Kubeconfig: path, Context: devContext, UserAgent: "krivy-integration"})
	if err != nil {
		t.Fatalf("dev cluster client (run make dev-cluster dev-seed): %v", err)
	}
	if name != devContext {
		t.Fatalf("refusing to run against context %q", name)
	}
	return cs
}

func findImage(res *discovery.Result, sub string) *discovery.Image {
	for i := range res.Images {
		if strings.Contains(res.Images[i].Repository, sub) {
			return &res.Images[i]
		}
	}
	return nil
}

func namespaces(img *discovery.Image) map[string]bool {
	out := map[string]bool{}
	for _, w := range img.Workloads {
		out[w.Namespace] = true
	}
	return out
}

func TestDiscoveryClusterVsNamespace(t *testing.T) {
	cs := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := discovery.NewKubernetes(cs, discovery.Options{ExcludeNamespaces: []string{"kube-system", jobNamespace}})

	all, err := d.Discover(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	busybox := findImage(all, "library/busybox")
	if busybox == nil {
		t.Fatalf("busybox not discovered: %+v", all.Images)
	}
	// One deduplicated identity shared by both namespaces.
	ns := namespaces(busybox)
	if !ns["production"] || !ns["staging"] {
		t.Fatalf("busybox should be used in production and staging, got %v", ns)
	}
	if busybox.Digest == "" || !strings.Contains(busybox.Key, "@sha256:") {
		t.Errorf("expected digest-pinned key from running imageID, got key=%q digest=%q", busybox.Key, busybox.Digest)
	}
	keys := map[string]int{}
	for _, img := range all.Images {
		keys[img.Key]++
	}
	for k, n := range keys {
		if n != 1 {
			t.Errorf("image %s listed %d times", k, n)
		}
	}
	alpine := findImage(all, "library/alpine")
	if alpine == nil {
		t.Fatal("alpine (init container) not discovered")
	}
	foundInit := false
	for _, w := range alpine.Workloads {
		if w.Namespace == "staging" && w.ContainerType == "init" {
			foundInit = true
		}
	}
	if !foundInit {
		t.Errorf("init container usage of alpine missing: %+v", alpine.Workloads)
	}

	staging, err := d.Discover(ctx, "staging")
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range staging.Images {
		for _, w := range img.Workloads {
			if w.Namespace != "staging" {
				t.Errorf("namespace discovery leaked %s/%s", w.Namespace, w.Name)
			}
		}
	}
	if findImage(staging, "library/busybox") == nil {
		t.Error("busybox missing from staging discovery")
	}
}

// stubConfig runs busybox printing a fixed Trivy report instead of Trivy, so
// the test is independent of the live vulnerability database.
func stubConfig(t *testing.T) scanner.Config {
	t.Helper()
	report, err := os.ReadFile(filepath.Join(repoRoot(), "internal", "scanner", "testdata", "vulnerable.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := scanner.ConfigFrom(config.Default())
	cfg.Namespace = jobNamespace
	cfg.Image = stubImage
	cfg.Timeout = 2 * time.Minute
	cfg.TTLAfterFinished = time.Minute
	cfg.PollInterval = time.Second
	cfg.SchedulingGracePeriod = time.Minute
	cfg.Command = []string{"sh", "-c", "echo " + base64.StdEncoding.EncodeToString(report) + " | base64 -d", "stub"}
	return cfg
}

func TestStubScannerJobLifecycle(t *testing.T) {
	cs := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg := stubConfig(t)
	sc := scanner.NewKubernetes(cs, cfg)
	target := scanner.Target{
		ScanJobID: "it-" + time.Now().Format("150405"), ImageKey: "docker.io/library/alpine:3.19.1",
		ImageRef: "docker.io/library/alpine:3.19.1", Attempt: 1,
	}
	res, err := sc.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities parsed from collected pod logs")
	}
	for _, v := range res.Vulnerabilities {
		if v.Severity != "CRITICAL" {
			t.Errorf("non-critical vulnerability leaked: %+v", v)
		}
	}
	job, err := cs.BatchV1().Jobs(jobNamespace).Get(ctx, res.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("job %s: %v", res.JobName, err)
	}
	spec := job.Spec.Template.Spec
	for _, v := range spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			t.Errorf("scanner job must not use a PVC (volume %s)", v.Name)
		}
	}
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("scanner job must not mount a service account token")
	}
	if job.Spec.TTLSecondsAfterFinished == nil || job.Spec.ActiveDeadlineSeconds == nil {
		t.Error("scanner job needs TTL and active deadline")
	}

	// Re-attaching to the same (finished) Job collects the same result.
	again, err := sc.Scan(ctx, target)
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if again.JobName != res.JobName || len(again.Vulnerabilities) != len(res.Vulnerabilities) {
		t.Errorf("re-attach mismatch: %s/%d vs %s/%d", again.JobName, len(again.Vulnerabilities), res.JobName, len(res.Vulnerabilities))
	}
	_ = cs.BatchV1().Jobs(jobNamespace).Delete(context.Background(), res.JobName, metav1.DeleteOptions{PropagationPolicy: ptr(metav1.DeletePropagationBackground)})
}

func TestStubScannerImagePullFailure(t *testing.T) {
	cs := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg := stubConfig(t)
	cfg.Image = "registry.invalid/krivy/does-not-exist:0"
	cfg.SchedulingGracePeriod = 20 * time.Second
	_, err := scanner.NewKubernetes(cs, cfg).Scan(ctx, scanner.Target{
		ScanJobID: "it-pull-" + time.Now().Format("150405"), ImageKey: "x", ImageRef: "alpine:3.19.1", Attempt: 1,
	})
	var se *scanner.Error
	if !errors.As(err, &se) || se.Kind != scanner.KindScheduling || !se.Retryable {
		t.Fatalf("expected retryable scheduling error, got %v", err)
	}
}

type recorder struct{ events []notify.Event }

func (r *recorder) Notify(_ context.Context, ev notify.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func runScan(t *testing.T, o *orchestrator.Orchestrator, st store.Store, scope, ns string) *store.ScanRun {
	t.Helper()
	ctx := context.Background()
	run, _, err := o.Enqueue(ctx, scope, ns, store.TriggerAPI, "integration")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		cur, err := st.GetScanRun(ctx, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if cur.Terminal() {
			return cur
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("scan %s did not finish", run.ID)
	return nil
}

func TestEndToEndOrchestratorWithStubScanner(t *testing.T) {
	cs := client(t)
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "krivy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rec := &recorder{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	o := orchestrator.New(st,
		discovery.NewKubernetes(cs, discovery.Options{ExcludeNamespaces: []string{"kube-system", jobNamespace}}),
		scanner.NewKubernetes(cs, stubConfig(t)), rec,
		orchestrator.Options{MaxConcurrentJobs: 2, MaxAttempts: 1}, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = o.Run(ctx) }()

	cluster := runScan(t, o, st, store.ScopeCluster, "")
	if cluster.Status != store.StatusSucceeded || cluster.TotalImages < 2 {
		t.Fatalf("cluster scan: status=%s images=%d err=%s", cluster.Status, cluster.TotalImages, cluster.Error)
	}
	open := "open"
	all, total, err := st.ListFindings(ctx, store.FindingFilter{Status: open})
	if err != nil || total == 0 {
		t.Fatalf("expected findings after cluster scan: %v total=%d", err, total)
	}
	if len(rec.events) == 0 || rec.events[0].Type != config.EventNewCritical {
		t.Fatalf("expected a new_critical event, got %+v", rec.events)
	}

	// A namespace scan must not resolve or deactivate anything elsewhere.
	staging := runScan(t, o, st, store.ScopeNamespace, "staging")
	if staging.Status != store.StatusSucceeded {
		t.Fatalf("staging scan: %s %s", staging.Status, staging.Error)
	}
	after, _, _ := st.ListFindings(ctx, store.FindingFilter{Status: open, Page: store.Page{Limit: 500}})
	if len(after) != len(all) {
		t.Errorf("namespace scan changed open findings: %d -> %d", len(all), len(after))
	}
	prod, _, _ := st.ListFindings(ctx, store.FindingFilter{Status: open, Namespace: "production"})
	if len(prod) == 0 {
		t.Error("production findings disappeared after a staging scan")
	}
	if staging.NewFindings != 0 {
		t.Errorf("rescanning unchanged images reported %d new findings", staging.NewFindings)
	}
	cleanupJobs(t, cs)
}

func TestRealTrivyScan(t *testing.T) {
	cs := client(t)
	if os.Getenv("KRIVY_INTEGRATION_REAL_TRIVY") != "1" {
		t.Skip("set KRIVY_INTEGRATION_REAL_TRIVY=1 to run a real Trivy scan")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cfg := scanner.ConfigFrom(config.Default())
	cfg.Namespace = jobNamespace
	res, err := scanner.NewKubernetes(cs, cfg).Scan(ctx, scanner.Target{
		ScanJobID: "it-real-" + time.Now().Format("150405"), ImageKey: "alpine", ImageRef: "docker.io/library/alpine:3.19.1", Attempt: 1,
	})
	if err != nil {
		t.Fatalf("real trivy scan: %v", err)
	}
	t.Logf("real trivy: %d critical vulnerabilities in %s (job %s)", len(res.Vulnerabilities), res.ImageRef, res.JobName)
}

func cleanupJobs(t *testing.T, cs kubernetes.Interface) {
	t.Helper()
	_ = cs.BatchV1().Jobs(jobNamespace).DeleteCollection(context.Background(),
		metav1.DeleteOptions{PropagationPolicy: ptr(metav1.DeletePropagationBackground)},
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/component=scanner"})
}

func ptr[T any](v T) *T { return &v }
