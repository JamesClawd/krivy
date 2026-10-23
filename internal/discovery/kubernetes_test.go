package discovery

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	dNginx = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dApp   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dBusy  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	dDbg   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

func tru() *bool { b := true; return &b }

func owned(kind, name string) []metav1.OwnerReference {
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: tru()}}
}

type ctr struct {
	name, image, imageID string
}

func mkPod(ns, name string, phase corev1.PodPhase, owners []metav1.OwnerReference, containers, inits, ephs []ctr) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owners},
		Status:     corev1.PodStatus{Phase: phase},
	}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c.name, Image: c.image})
		if c.imageID != "-" {
			p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c.name, ImageID: c.imageID})
		}
	}
	for _, c := range inits {
		p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: c.name, Image: c.image})
		p.Status.InitContainerStatuses = append(p.Status.InitContainerStatuses, corev1.ContainerStatus{Name: c.name, ImageID: c.imageID})
	}
	for _, c := range ephs {
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: c.name, Image: c.image}})
		p.Status.EphemeralContainerStatuses = append(p.Status.EphemeralContainerStatuses, corev1.ContainerStatus{Name: c.name, ImageID: c.imageID})
	}
	return p
}

func rs(ns, name string, owners []metav1.OwnerReference) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owners}}
}

func job(ns, name string, owners []metav1.OwnerReference) *batchv1.Job {
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owners}}
}

func wl(ns, kind, name, c, t string) WorkloadRef {
	return WorkloadRef{Namespace: ns, Kind: kind, Name: name, Container: c, ContainerType: t}
}

func forbid(resource string) func(*fake.Clientset) {
	return func(c *fake.Clientset) {
		c.PrependReactor("get", resource, func(a k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "x", errors.New("rbac"))
		})
	}
}

func TestDiscover(t *testing.T) {
	tests := []struct {
		name      string
		objs      []runtime.Object
		opts      Options
		namespace string
		setup     func(*fake.Clientset)
		want      []Image
		wantWarn  []string // substrings, each must appear in some warning
		noWarn    bool
	}{
		{
			name: "deployment and statefulset share digest across namespaces",
			objs: []runtime.Object{
				rs("a", "web-7d9", owned("Deployment", "web")),
				mkPod("a", "web-7d9-x", corev1.PodRunning, owned("ReplicaSet", "web-7d9"),
					[]ctr{{"nginx", "nginx:1.27", "docker-pullable://nginx@" + dNginx}}, nil, nil),
				mkPod("a", "web-7d9-y", corev1.PodRunning, owned("ReplicaSet", "web-7d9"),
					[]ctr{{"nginx", "nginx:1.27", "docker.io/library/nginx@" + dNginx}}, nil, nil),
				mkPod("b", "db-0", corev1.PodRunning, owned("StatefulSet", "db"),
					[]ctr{{"proxy", "docker.io/library/nginx:1.27", "docker.io/library/nginx@" + dNginx}}, nil, nil),
			},
			want: []Image{{
				Key: "docker.io/library/nginx@" + dNginx, Repository: "docker.io/library/nginx", Digest: dNginx,
				Ref: "docker.io/library/nginx@" + dNginx,
				Workloads: []WorkloadRef{
					wl("a", "Deployment", "web", "nginx", "container"),
					wl("b", "StatefulSet", "db", "proxy", "container"),
				},
			}},
			noWarn: true,
		},
		{
			name: "init and ephemeral containers, cronjob owner, bare sha imageID",
			objs: []runtime.Object{
				job("a", "backup-123", owned("CronJob", "backup")),
				mkPod("a", "backup-123-z", corev1.PodRunning, owned("Job", "backup-123"),
					[]ctr{{"main", "ghcr.io/org/app:v1", "ghcr.io/org/app@" + dApp}},
					[]ctr{{"init", "busybox", dBusy}},
					[]ctr{{"debug", "ghcr.io/org/debug:1", "ghcr.io/org/debug@" + dDbg}}),
			},
			want: []Image{
				{Key: "docker.io/library/busybox@" + dBusy, Repository: "docker.io/library/busybox", Digest: dBusy,
					Ref: "docker.io/library/busybox@" + dBusy, Workloads: []WorkloadRef{wl("a", "CronJob", "backup", "init", "init")}},
				{Key: "ghcr.io/org/app@" + dApp, Repository: "ghcr.io/org/app", Digest: dApp,
					Ref: "ghcr.io/org/app@" + dApp, Workloads: []WorkloadRef{wl("a", "CronJob", "backup", "main", "container")}},
				{Key: "ghcr.io/org/debug@" + dDbg, Repository: "ghcr.io/org/debug", Digest: dDbg,
					Ref: "ghcr.io/org/debug@" + dDbg, Workloads: []WorkloadRef{wl("a", "CronJob", "backup", "debug", "ephemeral")}},
			},
			noWarn: true,
		},
		{
			name: "pending pod without imageID falls back to spec ref with warning; completed pods skipped",
			objs: []runtime.Object{
				mkPod("a", "solo", corev1.PodPending, nil, []ctr{{"app", "localhost:5000/team/app", "-"}}, nil, nil),
				mkPod("a", "done", corev1.PodSucceeded, nil, []ctr{{"app", "alpine:3", "docker.io/library/alpine@" + dApp}}, nil, nil),
				mkPod("a", "dead", corev1.PodFailed, nil, []ctr{{"app", "alpine:3", "docker.io/library/alpine@" + dApp}}, nil, nil),
			},
			want: []Image{{
				Key: "localhost:5000/team/app:latest", Repository: "localhost:5000/team/app",
				Ref: "localhost:5000/team/app:latest", Workloads: []WorkloadRef{wl("a", "Pod", "solo", "app", "container")},
			}},
			wantWarn: []string{"a/solo", "digest unknown"},
		},
		{
			name: "spec digest used when imageID missing (no warning)",
			objs: []runtime.Object{
				mkPod("a", "p", corev1.PodPending, nil, []ctr{{"app", "quay.io/x/y@" + dApp, ""}}, nil, nil),
			},
			want: []Image{{
				Key: "quay.io/x/y@" + dApp, Repository: "quay.io/x/y", Digest: dApp, Ref: "quay.io/x/y@" + dApp,
				Workloads: []WorkloadRef{wl("a", "Pod", "p", "app", "container")},
			}},
			noWarn: true,
		},
		{
			name: "forbidden owner lookups fall back to immediate owner",
			objs: []runtime.Object{
				rs("a", "web-1", owned("Deployment", "web")),
				job("a", "j-1", owned("CronJob", "cj")),
				mkPod("a", "web-1-a", corev1.PodRunning, owned("ReplicaSet", "web-1"), []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
				mkPod("a", "j-1-a", corev1.PodRunning, owned("Job", "j-1"), []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
			},
			setup: func(c *fake.Clientset) { forbid("replicasets")(c); forbid("jobs")(c) },
			want: []Image{{
				Key: "docker.io/library/nginx@" + dNginx, Repository: "docker.io/library/nginx", Digest: dNginx,
				Ref:       "docker.io/library/nginx@" + dNginx,
				Workloads: []WorkloadRef{wl("a", "Job", "j-1", "c", "container"), wl("a", "ReplicaSet", "web-1", "c", "container")},
			}},
			wantWarn: []string{"ReplicaSet a/web-1", "Job a/j-1", "forbidden"},
		},
		{
			name: "missing replicaset (not found) and RS without owner",
			objs: []runtime.Object{
				rs("a", "bare", nil),
				mkPod("a", "bare-x", corev1.PodRunning, owned("ReplicaSet", "bare"), []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
				mkPod("a", "gone-x", corev1.PodRunning, owned("ReplicaSet", "gone"), []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
				mkPod("a", "ds-x", corev1.PodRunning, owned("DaemonSet", "ds"), []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
			},
			want: []Image{{
				Key: "docker.io/library/nginx@" + dNginx, Repository: "docker.io/library/nginx", Digest: dNginx,
				Ref: "docker.io/library/nginx@" + dNginx,
				Workloads: []WorkloadRef{
					wl("a", "DaemonSet", "ds", "c", "container"),
					wl("a", "ReplicaSet", "bare", "c", "container"),
					wl("a", "ReplicaSet", "gone", "c", "container"),
				},
			}},
			wantWarn: []string{"ReplicaSet a/gone"},
		},
		{
			name: "excluded namespaces skipped cluster-wide",
			opts: Options{ExcludeNamespaces: []string{"kube-system"}},
			objs: []runtime.Object{
				mkPod("kube-system", "k", corev1.PodRunning, nil, []ctr{{"c", "registry.k8s.io/pause:3.9", "registry.k8s.io/pause@" + dBusy}}, nil, nil),
				mkPod("a", "p", corev1.PodRunning, nil, []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
			},
			want: []Image{{
				Key: "docker.io/library/nginx@" + dNginx, Repository: "docker.io/library/nginx", Digest: dNginx,
				Ref: "docker.io/library/nginx@" + dNginx, Workloads: []WorkloadRef{wl("a", "Pod", "p", "c", "container")},
			}},
			noWarn: true,
		},
		{
			name:      "single namespace",
			namespace: "b",
			objs: []runtime.Object{
				mkPod("a", "p", corev1.PodRunning, nil, []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil),
				mkPod("b", "q", corev1.PodRunning, nil, []ctr{{"c", "ghcr.io/org/app:v1", "ghcr.io/org/app@" + dApp}}, nil, nil),
			},
			want: []Image{{
				Key: "ghcr.io/org/app@" + dApp, Repository: "ghcr.io/org/app", Digest: dApp,
				Ref: "ghcr.io/org/app@" + dApp, Workloads: []WorkloadRef{wl("b", "Pod", "q", "c", "container")},
			}},
			noWarn: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset(tc.objs...)
			if tc.setup != nil {
				tc.setup(c)
			}
			res, err := NewKubernetes(c, tc.opts).Discover(context.Background(), tc.namespace)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if !reflect.DeepEqual(res.Images, tc.want) {
				t.Errorf("images mismatch\n got: %+v\nwant: %+v", res.Images, tc.want)
			}
			if tc.noWarn && len(res.Warnings) > 0 {
				t.Errorf("unexpected warnings: %v", res.Warnings)
			}
			all := strings.Join(res.Warnings, "\n")
			for _, w := range tc.wantWarn {
				if !strings.Contains(all, w) {
					t.Errorf("warnings %q missing %q", all, w)
				}
			}
		})
	}
}

func TestDiscoverListForbidden(t *testing.T) {
	c := fake.NewClientset()
	c.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("no rbac"))
	})
	_, err := NewKubernetes(c, Options{}).Discover(context.Background(), "")
	if err == nil || !apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "list pods") {
		t.Fatalf("want wrapped forbidden error, got %v", err)
	}
}

func TestDiscoverPaginates(t *testing.T) {
	c := fake.NewClientset()
	calls := 0
	c.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		opts := a.(k8stesting.ListActionImpl).GetListOptions()
		if opts.Limit != 500 {
			t.Errorf("limit = %d", opts.Limit)
		}
		if opts.Continue == "" {
			l := &corev1.PodList{Items: []corev1.Pod{*mkPod("a", "p1", corev1.PodRunning, nil, []ctr{{"c", "nginx", "nginx@" + dNginx}}, nil, nil)}}
			l.Continue = "tok"
			return true, l, nil
		}
		if opts.Continue != "tok" {
			t.Errorf("continue = %q", opts.Continue)
		}
		return true, &corev1.PodList{Items: []corev1.Pod{*mkPod("a", "p2", corev1.PodRunning, nil, []ctr{{"c", "alpine", "alpine@" + dApp}}, nil, nil)}}, nil
	})
	res, err := NewKubernetes(c, Options{}).Discover(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(res.Images) != 2 {
		t.Fatalf("calls=%d images=%d", calls, len(res.Images))
	}
}

func TestParseImage(t *testing.T) {
	tests := map[string]string{
		"nginx":                         "docker.io/library/nginx:latest",
		"nginx:1.27":                    "docker.io/library/nginx:1.27",
		"bitnami/redis:7":               "docker.io/bitnami/redis:7",
		"index.docker.io/library/nginx": "docker.io/library/nginx:latest",
		"localhost:5000/app":            "localhost:5000/app:latest",
		"localhost/app:v2":              "localhost/app:v2",
		"GHCR.io/org/app:v1":            "ghcr.io/org/app:v1",
		"ghcr.io/org/app:v1@" + dApp:    "ghcr.io/org/app@" + dApp,
		"registry:5000/a/b/c:1.0":       "registry:5000/a/b/c:1.0",
	}
	for in, want := range tests {
		if got := parseImage(in).String(); got != want {
			t.Errorf("parseImage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseImageID(t *testing.T) {
	tests := []struct {
		in, repo, digest string
		ok               bool
	}{
		{"docker-pullable://nginx@" + dNginx, "docker.io/library/nginx", dNginx, true},
		{"docker.io/library/nginx@" + dNginx, "docker.io/library/nginx", dNginx, true},
		{"ghcr.io/org/app:v1@" + dApp, "ghcr.io/org/app", dApp, true},
		{dBusy, "", dBusy, true},
		{"docker://" + dBusy, "", dBusy, true},
		{"", "", "", false},
		{"sha256:abc", "", "", false},
		{"nginx:latest", "", "", false},
	}
	for _, tc := range tests {
		repo, d, ok := parseImageID(tc.in)
		if repo != tc.repo || d != tc.digest || ok != tc.ok {
			t.Errorf("parseImageID(%q) = %q %q %v", tc.in, repo, d, ok)
		}
	}
}
