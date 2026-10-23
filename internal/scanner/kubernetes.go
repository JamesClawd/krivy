package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	logTailBytes = 4096
	// deadlineSlack is how long past activeDeadlineSeconds we keep polling
	// before giving up locally (the Job controller should have failed it).
	deadlineSlack = 90 * time.Second
	// maxConsecutiveAPIErrors tolerated while polling.
	maxConsecutiveAPIErrors = 5
)

type kubeScanner struct {
	client kubernetes.Interface
	cfg    Config
	logs   LogFetcher
	now    func() time.Time
}

// NewKubernetes returns a Scanner that runs one Trivy Job per Scan call.
func NewKubernetes(client kubernetes.Interface, cfg Config) Scanner {
	cfg = cfg.withDefaults()
	s := &kubeScanner{client: client, cfg: cfg, logs: cfg.Logs, now: time.Now}
	if s.logs == nil {
		s.logs = func(ctx context.Context, ns, pod string, opts *corev1.PodLogOptions) ([]byte, error) {
			rc, err := client.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			if opts.LimitBytes != nil {
				return io.ReadAll(io.LimitReader(rc, *opts.LimitBytes))
			}
			return io.ReadAll(rc)
		}
	}
	return s
}

func kerr(msg string, err error) *Error {
	retry := !(apierrors.IsForbidden(err) || apierrors.IsInvalid(err) || apierrors.IsUnauthorized(err))
	return &Error{Kind: KindKubernetes, Retryable: retry, Msg: msg, Err: err}
}

func (s *kubeScanner) Scan(ctx context.Context, t Target) (*Result, error) {
	started := s.now()
	want := BuildJob(s.cfg, t)
	jobs := s.client.BatchV1().Jobs(s.cfg.Namespace)

	job, err := jobs.Create(ctx, want, metav1.CreateOptions{})
	reused := false
	if apierrors.IsAlreadyExists(err) {
		job, err = jobs.Get(ctx, want.Name, metav1.GetOptions{})
		reused = true
	}
	if err != nil {
		if ctx.Err() != nil {
			s.onCancel(ctx, want.Name)
			return nil, ctx.Err()
		}
		return nil, kerr("create scanner job "+want.Name, err)
	}

	res, err := s.wait(ctx, t, job)
	if ctx.Err() != nil {
		s.onCancel(ctx, want.Name)
		return nil, ctx.Err()
	}
	if err != nil {
		if se, ok := err.(*Error); ok {
			if se.Kind == KindScheduling || se.Kind == KindTimeout {
				// Pods stuck pending would otherwise linger until the deadline.
				s.cleanup(want.Name)
			}
			se.Diagnostics = strings.TrimSpace(fmt.Sprintf("job=%s reused=%v elapsed=%s\n%s",
				want.Name, reused, s.now().Sub(started).Round(time.Second), se.Diagnostics))
		}
		return nil, err
	}
	res.JobName = want.Name
	res.Diagnostics = strings.TrimSpace(fmt.Sprintf("job=%s reused=%v elapsed=%s %s",
		want.Name, reused, s.now().Sub(started).Round(time.Second), res.Diagnostics))
	return res, nil
}

// onCancel deletes the Job only for a user cancellation (cause
// ErrScanCancelled). Any other cancellation, e.g. controller shutdown, leaves
// the Job running so a restarted controller re-attaches via AlreadyExists.
func (s *kubeScanner) onCancel(ctx context.Context, name string) {
	if errors.Is(context.Cause(ctx), ErrScanCancelled) {
		s.cleanup(name)
	}
}

// cleanup deletes the Job (and, via background propagation, its Pods) using
// a context detached from the caller's cancellation.
func (s *kubeScanner) cleanup(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	prop := metav1.DeletePropagationBackground
	_ = s.client.BatchV1().Jobs(s.cfg.Namespace).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &prop})
}

func jobCondition(job *batchv1.Job, typ batchv1.JobConditionType) *batchv1.JobCondition {
	for i := range job.Status.Conditions {
		c := &job.Status.Conditions[i]
		if c.Type == typ && c.Status == corev1.ConditionTrue {
			return c
		}
	}
	return nil
}

func (s *kubeScanner) wait(ctx context.Context, t Target, job *batchv1.Job) (*Result, error) {
	name := job.Name
	start := job.CreationTimestamp.Time
	if start.IsZero() {
		start = s.now()
	}
	localDeadline := start.Add(s.cfg.Timeout + deadlineSlack)
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()
	apiErrors := 0

	for {
		if c := jobCondition(job, batchv1.JobComplete); c != nil {
			return s.collect(ctx, job)
		}
		if c := jobCondition(job, batchv1.JobSuccessCriteriaMet); c != nil {
			return s.collect(ctx, job)
		}
		if c := jobCondition(job, batchv1.JobFailed); c != nil {
			return nil, s.classifyFailure(ctx, job, c)
		}
		if err := s.checkPending(ctx, name, start); err != nil {
			return nil, err
		}
		if s.now().After(localDeadline) {
			return nil, &Error{Kind: KindTimeout, Retryable: true,
				Msg: fmt.Sprintf("scanner job %s did not finish within %s", name, s.cfg.Timeout)}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
		j, err := s.client.BatchV1().Jobs(s.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
		switch {
		case err == nil:
			job, apiErrors = j, 0
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case apierrors.IsNotFound(err):
			return nil, &Error{Kind: KindKubernetes, Retryable: true, Msg: "scanner job " + name + " disappeared", Err: err}
		default:
			apiErrors++
			if apiErrors >= maxConsecutiveAPIErrors {
				return nil, kerr("get scanner job "+name, err)
			}
		}
	}
}

// pods returns the Job's pods, newest first.
func (s *kubeScanner) pods(ctx context.Context, jobName string) ([]corev1.Pod, error) {
	podsAPI := s.client.CoreV1().Pods(s.cfg.Namespace)
	var items []corev1.Pod
	for _, sel := range []string{"batch.kubernetes.io/job-name=" + jobName, "job-name=" + jobName} {
		list, err := podsAPI.List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return nil, err
		}
		if len(list.Items) > 0 {
			items = list.Items
			break
		}
	}
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].CreationTimestamp.After(items[j-1].CreationTimestamp.Time); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
	return items, nil
}

var pullFailureReasons = map[string]bool{
	"ErrImagePull": true, "ImagePullBackOff": true, "InvalidImageName": true,
	"ErrImageNeverPull": true, "CreateContainerConfigError": true,
}

// checkPending fails with KindScheduling when the scanner pod is
// unschedulable or cannot pull the Trivy image beyond the grace period.
func (s *kubeScanner) checkPending(ctx context.Context, jobName string, start time.Time) error {
	if s.now().Sub(start) < s.cfg.SchedulingGracePeriod {
		return nil
	}
	pods, err := s.pods(ctx, jobName)
	if err != nil || len(pods) == 0 {
		return nil // transient; the deadline still applies
	}
	pod := &pods[0]
	if pod.Status.Phase != corev1.PodPending {
		return nil
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return &Error{Kind: KindScheduling, Retryable: true,
				Msg:         "scanner pod unschedulable",
				Diagnostics: podSummary(pod) + "\n" + redact(c.Message)}
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && pullFailureReasons[w.Reason] {
			return &Error{Kind: KindScheduling, Retryable: true,
				Msg:         fmt.Sprintf("scanner pod cannot start: %s", w.Reason),
				Diagnostics: podSummary(pod) + "\n" + redact(w.Message)}
		}
	}
	return nil
}

func (s *kubeScanner) collect(ctx context.Context, job *batchv1.Job) (*Result, error) {
	pods, err := s.pods(ctx, job.Name)
	if err != nil {
		return nil, kerr("list scanner pods", err)
	}
	var pod *corev1.Pod
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodSucceeded {
			pod = &pods[i]
			break
		}
	}
	if pod == nil && len(pods) > 0 {
		pod = &pods[0]
	}
	if pod == nil {
		return nil, &Error{Kind: KindOutput, Retryable: true, Msg: "scanner job completed but its pod is gone (logs unavailable)"}
	}
	limit := s.cfg.MaxOutputBytes + 1
	out, err := s.logs(ctx, s.cfg.Namespace, pod.Name, &corev1.PodLogOptions{Container: ContainerName, LimitBytes: &limit})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, kerr("read scanner logs", err)
	}
	if int64(len(out)) > s.cfg.MaxOutputBytes {
		return nil, &Error{Kind: KindOutput, Retryable: false,
			Msg: fmt.Sprintf("output too large (> %d bytes)", s.cfg.MaxOutputBytes)}
	}
	res, err := ParseReport(bytes.NewReader(out), s.cfg.Severities)
	if err != nil {
		return nil, err
	}
	res.Diagnostics = fmt.Sprintf("output=%dB vulnerabilities=%d", len(out), len(res.Vulnerabilities))
	return res, nil
}

func (s *kubeScanner) classifyFailure(ctx context.Context, job *batchv1.Job, cond *batchv1.JobCondition) error {
	var (
		pod     *corev1.Pod
		logTail string
	)
	if pods, err := s.pods(ctx, job.Name); err == nil && len(pods) > 0 {
		pod = &pods[0]
		n := int64(64 << 10)
		tailLines := int64(200)
		if b, err := s.logs(ctx, s.cfg.Namespace, pod.Name, &corev1.PodLogOptions{Container: ContainerName, TailLines: &tailLines, LimitBytes: &n}); err == nil {
			logTail = tail(b, logTailBytes)
		}
	}
	var term *corev1.ContainerStateTerminated
	if pod != nil {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name == ContainerName && cs.State.Terminated != nil {
				term = cs.State.Terminated
			}
		}
		if logTail == "" && term != nil {
			logTail = tail([]byte(term.Message), logTailBytes)
		}
	}

	var diag strings.Builder
	fmt.Fprintf(&diag, "job condition: %s: %s", cond.Reason, cond.Message)
	if pod != nil {
		diag.WriteString("\n" + podSummary(pod))
	}
	if logTail != "" {
		diag.WriteString("\n--- log tail ---\n" + redact(logTail))
	}
	e := &Error{Diagnostics: diag.String()}

	lower := strings.ToLower(logTail)
	switch {
	case cond.Reason == batchv1.JobReasonDeadlineExceeded || (pod != nil && pod.Status.Reason == "DeadlineExceeded"):
		e.Kind, e.Retryable, e.Msg = KindTimeout, true, "scanner job exceeded its deadline"
	case strings.Contains(lower, "failed to download vulnerability db") ||
		strings.Contains(lower, "toomanyrequests") ||
		strings.Contains(lower, "db download error") ||
		strings.Contains(lower, "failed to download artifact"):
		e.Kind, e.Retryable, e.Msg = KindScanner, true, "vulnerability DB download failed"
	case isImageFetchError(lower):
		e.Kind, e.Retryable, e.Msg = KindImagePull, false, "trivy could not fetch the image (auth or not found)"
	case term != nil && term.Reason == "OOMKilled":
		e.Kind, e.Retryable, e.Msg = KindScanner, true, "scanner OOMKilled"
	default:
		e.Kind, e.Retryable = KindScanner, true
		e.Msg = "trivy failed"
		if term != nil {
			e.Msg = fmt.Sprintf("trivy exited with code %d (%s)", term.ExitCode, term.Reason)
		}
	}
	return e
}

var imageFetchMarkers = []string{
	"unauthorized", "authentication required", "denied", "manifest_unknown",
	"manifest unknown", "name_unknown", "name unknown", "unable to find the specified image",
}

func isImageFetchError(lower string) bool {
	for _, m := range imageFetchMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	for _, line := range strings.Split(lower, "\n") {
		if strings.Contains(line, "not found") &&
			(strings.Contains(line, "image") || strings.Contains(line, "manifest") || strings.Contains(line, "repository")) {
			return true
		}
	}
	return false
}

func podSummary(pod *corev1.Pod) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pod %s phase=%s", pod.Name, pod.Status.Phase)
	if pod.Status.Reason != "" {
		fmt.Fprintf(&b, " reason=%s", pod.Status.Reason)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		switch {
		case cs.State.Waiting != nil:
			fmt.Fprintf(&b, " container=%s waiting=%s", cs.Name, cs.State.Waiting.Reason)
		case cs.State.Terminated != nil:
			fmt.Fprintf(&b, " container=%s exitCode=%d reason=%s", cs.Name, cs.State.Terminated.ExitCode, cs.State.Terminated.Reason)
		}
	}
	return b.String()
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)\S+`),
	regexp.MustCompile(`(?i)((?:password|passwd|token|secret|auth)["']?\s*[:=]\s*["']?)[^\s"',}]+`),
	regexp.MustCompile(`(?i)(https?://[^:/\s]+:)[^@\s]+(@)`),
}

// redact masks credential-looking substrings in diagnostics.
func redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "${1}[REDACTED]${2}")
	}
	return s
}
