package discovery

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Options configures the Kubernetes discoverer.
type Options struct {
	// ExcludeNamespaces are skipped during cluster-wide discovery
	// (namespace ""). An explicitly requested namespace is always listed.
	ExcludeNamespaces []string
	// PageSize is the List page size; default 500.
	PageSize int64
}

type kubeDiscoverer struct {
	client  kubernetes.Interface
	exclude map[string]bool
	limit   int64
}

// NewKubernetes returns a Discoverer that uses only read-only API calls:
// list pods, get replicasets, get jobs.
func NewKubernetes(client kubernetes.Interface, opts Options) Discoverer {
	ex := make(map[string]bool, len(opts.ExcludeNamespaces))
	for _, n := range opts.ExcludeNamespaces {
		ex[n] = true
	}
	limit := opts.PageSize
	if limit <= 0 {
		limit = 500
	}
	return &kubeDiscoverer{client: client, exclude: ex, limit: limit}
}

type ownerKey struct{ ns, kind, name string }

type ownerRef struct{ kind, name string }

// pass holds per-Discover state (owner cache, warnings).
type pass struct {
	d        *kubeDiscoverer
	owners   map[ownerKey]ownerRef
	warnings []string
	warned   map[string]bool
	images   map[string]*Image
	refs     map[string]map[WorkloadRef]bool
}

func (p *pass) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.warned[msg] {
		return
	}
	p.warned[msg] = true
	p.warnings = append(p.warnings, msg)
}

func (d *kubeDiscoverer) Discover(ctx context.Context, namespace string) (*Result, error) {
	p := &pass{
		d:      d,
		owners: map[ownerKey]ownerRef{},
		warned: map[string]bool{},
		images: map[string]*Image{},
		refs:   map[string]map[WorkloadRef]bool{},
	}
	opts := metav1.ListOptions{Limit: d.limit}
	for {
		list, err := d.client.CoreV1().Pods(namespace).List(ctx, opts)
		if err != nil {
			scope := "all namespaces"
			if namespace != "" {
				scope = "namespace " + namespace
			}
			return nil, fmt.Errorf("discovery: list pods in %s: %w", scope, err)
		}
		for i := range list.Items {
			pod := &list.Items[i]
			if namespace == "" && d.exclude[pod.Namespace] {
				continue
			}
			if pod.Status.Phase != corev1.PodPending && pod.Status.Phase != corev1.PodRunning {
				continue
			}
			p.addPod(ctx, pod)
		}
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}

	res := &Result{Images: make([]Image, 0, len(p.images)), Warnings: p.warnings}
	for key, img := range p.images {
		for w := range p.refs[key] {
			img.Workloads = append(img.Workloads, w)
		}
		sortWorkloads(img.Workloads)
		res.Images = append(res.Images, *img)
	}
	sort.Slice(res.Images, func(i, j int) bool { return res.Images[i].Key < res.Images[j].Key })
	return res, nil
}

func sortWorkloads(ws []WorkloadRef) {
	sort.Slice(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.ContainerType != b.ContainerType {
			return a.ContainerType < b.ContainerType
		}
		return a.Container < b.Container
	})
}

const (
	typeContainer = "container"
	typeInit      = "init"
	typeEphemeral = "ephemeral"
)

func (p *pass) addPod(ctx context.Context, pod *corev1.Pod) {
	owner := p.resolveOwner(ctx, pod)
	statusByName := func(sts []corev1.ContainerStatus) map[string]corev1.ContainerStatus {
		m := make(map[string]corev1.ContainerStatus, len(sts))
		for _, s := range sts {
			m[s.Name] = s
		}
		return m
	}
	add := func(name, image, ctype string, sts map[string]corev1.ContainerStatus) {
		imageID := ""
		if s, ok := sts[name]; ok {
			imageID = s.ImageID
		}
		p.addImage(pod, owner, name, image, imageID, ctype)
	}
	regular := statusByName(pod.Status.ContainerStatuses)
	for _, c := range pod.Spec.Containers {
		add(c.Name, c.Image, typeContainer, regular)
	}
	inits := statusByName(pod.Status.InitContainerStatuses)
	for _, c := range pod.Spec.InitContainers {
		add(c.Name, c.Image, typeInit, inits)
	}
	eph := statusByName(pod.Status.EphemeralContainerStatuses)
	for _, c := range pod.Spec.EphemeralContainers {
		add(c.Name, c.Image, typeEphemeral, eph)
	}
}

func (p *pass) addImage(pod *corev1.Pod, owner ownerRef, container, specImage, imageID, ctype string) {
	if specImage == "" {
		return
	}
	spec := parseImage(specImage)
	repo, digest := spec.Repository, spec.Digest
	if idRepo, idDigest, ok := parseImageID(imageID); ok {
		digest = idDigest
		if idRepo != "" {
			repo = idRepo
		}
	} else if digest == "" {
		p.warn("pod %s/%s container %q: running image digest unknown, using %s", pod.Namespace, pod.Name, container, spec.TagRef())
	}

	img := imageName{Repository: repo, Tag: spec.Tag, Digest: digest}
	key := img.String()
	if _, ok := p.images[key]; !ok {
		p.images[key] = &Image{Key: key, Repository: repo, Digest: digest, Ref: key}
		p.refs[key] = map[WorkloadRef]bool{}
	}
	p.refs[key][WorkloadRef{
		Namespace:     pod.Namespace,
		Kind:          owner.kind,
		Name:          owner.name,
		Container:     container,
		ContainerType: ctype,
	}] = true
}

func controllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

// resolveOwner returns the top-level workload of a pod: ReplicaSet ->
// Deployment and Job -> CronJob are followed via a read-only get; on any
// error the immediate owner is used.
func (p *pass) resolveOwner(ctx context.Context, pod *corev1.Pod) ownerRef {
	ref := controllerRef(pod.OwnerReferences)
	if ref == nil {
		return ownerRef{kind: "Pod", name: pod.Name}
	}
	immediate := ownerRef{kind: ref.Kind, name: ref.Name}
	if ref.Kind != "ReplicaSet" && ref.Kind != "Job" {
		return immediate
	}
	k := ownerKey{pod.Namespace, ref.Kind, ref.Name}
	if o, ok := p.owners[k]; ok {
		return o
	}
	var (
		parents []metav1.OwnerReference
		err     error
	)
	switch ref.Kind {
	case "ReplicaSet":
		rs, e := p.d.client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		err = e
		if e == nil {
			parents = rs.OwnerReferences
		}
	case "Job":
		job, e := p.d.client.BatchV1().Jobs(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		err = e
		if e == nil {
			parents = job.OwnerReferences
		}
	}
	out := immediate
	if err != nil {
		p.warn("resolve owner of %s %s/%s: %v (using %s)", ref.Kind, pod.Namespace, ref.Name, err, ref.Kind)
	} else if parent := controllerRef(parents); parent != nil {
		want := map[string]string{"ReplicaSet": "Deployment", "Job": "CronJob"}[ref.Kind]
		if parent.Kind == want {
			out = ownerRef{kind: parent.Kind, name: parent.Name}
		}
	}
	p.owners[k] = out
	return out
}
