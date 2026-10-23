package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and annotations set on scanner Jobs and their Pods.
const (
	LabelName       = "app.kubernetes.io/name"
	LabelComponent  = "app.kubernetes.io/component"
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	LabelScanJobID  = "krivy.io/scan-job-id"
	AnnotationImage = "krivy.io/image-ref"

	ContainerName = "trivy"
	cacheDir      = "/tmp/trivy-cache"
	dockerDir     = "/tmp/.docker"
	nonRootID     = int64(65534)
)

// JobName returns the deterministic Job name for a target:
// "krivy-scan-<short id>-<attempt>" (DNS-1123, <= 63 chars).
func JobName(t Target) string {
	short := sanitize(t.ScanJobID, 8)
	if short == "" {
		sum := sha256.Sum256([]byte(t.ImageKey + "|" + t.ImageRef))
		short = hex.EncodeToString(sum[:])[:8]
	}
	attempt := t.Attempt
	if attempt < 1 {
		attempt = 1
	}
	return fmt.Sprintf("krivy-scan-%s-%d", short, attempt)
}

// sanitize keeps [a-z0-9] up to max characters.
func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			if b.Len() == max {
				break
			}
		}
	}
	return b.String()
}

// labelValue makes s a valid label value (<= 63, alnum ends, [-_.a-zA-Z0-9]).
func labelValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
		if b.Len() == 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-_.")
}

// trivyTimeout leaves a margin so Trivy fails cleanly before the Job deadline.
func trivyTimeout(d time.Duration) time.Duration {
	margin := d / 10
	if margin < 30*time.Second {
		margin = 30 * time.Second
	}
	if margin > 2*time.Minute {
		margin = 2 * time.Minute
	}
	if d-margin < 30*time.Second {
		return d
	}
	return d - margin
}

func quantities(r ResourceList) corev1.ResourceList {
	out := corev1.ResourceList{}
	set := func(name corev1.ResourceName, v string) {
		if v == "" {
			return
		}
		if q, err := resource.ParseQuantity(v); err == nil {
			out[name] = q
		}
	}
	set(corev1.ResourceCPU, r.CPU)
	set(corev1.ResourceMemory, r.Memory)
	set(corev1.ResourceEphemeralStorage, r.EphemeralStorage)
	if len(out) == 0 {
		return nil
	}
	return out
}

// TrivyArgs returns the arguments after the "trivy" command.
func TrivyArgs(cfg Config, imageRef string) []string {
	cfg = cfg.withDefaults()
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--output", "/dev/stdout",
		"--scanners", "vuln",
		"--severity", strings.ToUpper(strings.Join(cfg.Severities, ",")),
		"--no-progress",
		"--cache-dir", cacheDir,
		"--timeout", trivyTimeout(cfg.Timeout).String(),
	}
	args = append(args, cfg.ExtraArgs...)
	// "--" guards against a ref that looks like a flag.
	return append(args, "--", imageRef)
}

// BuildJob renders the hardened scanner Job for t. It never uses a PVC and
// never mounts a ServiceAccount token.
func BuildJob(cfg Config, t Target) *batchv1.Job {
	cfg = cfg.withDefaults()
	name := JobName(t)
	labels := map[string]string{
		LabelName:      "krivy",
		LabelComponent: "scanner",
		LabelManagedBy: "krivy",
	}
	if v := labelValue(t.ScanJobID); v != "" {
		labels[LabelScanJobID] = v
	}
	podLabels := make(map[string]string, len(labels))
	for k, v := range labels {
		podLabels[k] = v
	}
	annotations := map[string]string{AnnotationImage: t.ImageRef}

	scratch := cfg.ScratchSizeLimit
	if scratch == "" {
		scratch = cfg.Resources.Limits.EphemeralStorage
	}
	if scratch == "" {
		scratch = "2Gi"
	}
	var sizeLimit *resource.Quantity
	if q, err := resource.ParseQuantity(scratch); err == nil {
		sizeLimit = &q
	}

	deadline := int64(cfg.Timeout / time.Second)
	if deadline < 1 {
		deadline = 1
	}
	ttl := int32(cfg.TTLAfterFinished / time.Second)

	volumes := []corev1.Volume{
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: sizeLimit}}},
		{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: sizeLimit}}},
	}
	mounts := []corev1.VolumeMount{
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "cache", MountPath: cacheDir},
	}
	env := []corev1.EnvVar{
		{Name: "HOME", Value: "/tmp"},
		{Name: "TMPDIR", Value: "/tmp"},
		{Name: "TRIVY_CACHE_DIR", Value: cacheDir},
		{Name: "TRIVY_NO_PROGRESS", Value: "true"},
		{Name: "TRIVY_DISABLE_VEX_NOTICE", Value: "true"},
	}
	if cfg.RegistrySecret != "" {
		mode := int32(0o440)
		volumes = append(volumes, corev1.Volume{Name: "registry-auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  cfg.RegistrySecret,
			Items:       []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: "config.json"}},
			DefaultMode: &mode,
		}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "registry-auth", MountPath: dockerDir, ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "DOCKER_CONFIG", Value: dockerDir})
	}
	var pullSecrets []corev1.LocalObjectReference
	for _, s := range cfg.ImagePullSecrets {
		if s != "" {
			pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: s})
		}
	}

	f, tr := false, true
	uid := nonRootID
	backoff := int32(0)
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: cfg.Namespace, Labels: labels, Annotations: annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   &deadline,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: annotations},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           cfg.ServiceAccount,
					AutomountServiceAccountToken: &f,
					EnableServiceLinks:           &f,
					ImagePullSecrets:             pullSecrets,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &tr,
						RunAsUser:      &uid,
						RunAsGroup:     &uid,
						FSGroup:        &uid,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Volumes: volumes,
					Containers: []corev1.Container{{
						Name:            ContainerName,
						Image:           cfg.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         command(cfg),
						Args:            TrivyArgs(cfg, t.ImageRef),
						Env:             env,
						VolumeMounts:    mounts,
						Resources: corev1.ResourceRequirements{
							Requests: quantities(cfg.Resources.Requests),
							Limits:   quantities(cfg.Resources.Limits),
						},
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &f,
							ReadOnlyRootFilesystem:   &tr,
							RunAsNonRoot:             &tr,
							Privileged:               &f,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
				},
			},
		},
	}
}

func command(cfg Config) []string {
	if len(cfg.Command) > 0 {
		return cfg.Command
	}
	return []string{"trivy"}
}
