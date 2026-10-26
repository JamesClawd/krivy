// Command krivy is the Krivy controller: it schedules Kubernetes image
// scans, runs one ephemeral Trivy Job per image, tracks critical CVE findings
// and serves the REST API, MCP endpoint and webhook notifications.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/l4r-s/krivy/internal/api"
	"github.com/l4r-s/krivy/internal/auth"
	"github.com/l4r-s/krivy/internal/config"
	"github.com/l4r-s/krivy/internal/discovery"
	"github.com/l4r-s/krivy/internal/httpserver"
	"github.com/l4r-s/krivy/internal/kube"
	"github.com/l4r-s/krivy/internal/mcpserver"
	"github.com/l4r-s/krivy/internal/notify"
	"github.com/l4r-s/krivy/internal/orchestrator"
	"github.com/l4r-s/krivy/internal/scanner"
	"github.com/l4r-s/krivy/internal/service"
	"github.com/l4r-s/krivy/internal/store"
	"github.com/l4r-s/krivy/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "krivy:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", os.Getenv("KRIVY_CONFIG"), "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "validate the configuration and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("krivy %s (%s)\n", version.Version, version.Commit)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)
	slog.SetDefault(log)
	if *checkConfig {
		if _, err := orchestrator.ParseSchedule(cfg.Scan.Schedule); cfg.Scan.Schedule != "" && err != nil {
			return err
		}
		fmt.Println("configuration OK")
		return nil
	}
	log.Info("starting krivy", "version", version.Version, "commit", version.Commit)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("database ready", "driver", cfg.Database.Driver, "schema_version", store.SchemaVersion())

	client, kctx, err := kube.NewClient(kube.Options{
		Kubeconfig: cfg.Kubernetes.Kubeconfig, Context: cfg.Kubernetes.Context,
		UserAgent: "krivy/" + version.Version,
	})
	if err != nil {
		return err
	}
	log.Info("kubernetes client ready", "context", kctx, "job_namespace", cfg.Kubernetes.JobNamespace)

	authn, err := auth.New(cfg.Auth.Tokens)
	if err != nil {
		return err
	}
	if !authn.Enabled() {
		log.Warn("no API tokens configured: REST and MCP requests will be rejected")
	}

	notifier, err := notify.New(cfg.Notifications, st, log.With("component", "notify"))
	if err != nil {
		return err
	}

	scfg := scanner.ConfigFrom(cfg)
	if err := scfg.Validate(); err != nil {
		return fmt.Errorf("trivy config: %w", err)
	}
	if cfg.Kubernetes.RegistrySecret != "" {
		log.Warn("kubernetes.registrySecret is deprecated; use kubernetes.registryAuth.existingSecrets")
	}
	if len(scfg.RegistrySecrets) > 0 {
		log.Info("registry auth configured", "secrets", scfg.RegistrySecrets, "namespace", scfg.Namespace)
	}
	disc := discovery.NewKubernetes(client, discovery.Options{ExcludeNamespaces: cfg.Kubernetes.ExcludeNamespaces})
	sc := scanner.NewKubernetes(client, scfg)
	orch := orchestrator.New(st, disc, sc, notifier, orchestrator.Options{
		MaxConcurrentJobs: cfg.Scan.MaxConcurrentJobs,
		MaxAttempts:       cfg.Scan.MaxAttempts,
		WatchNamespace:    cfg.Kubernetes.WatchNamespace,
	}, log.With("component", "orchestrator"))
	sched, err := orchestrator.NewScheduler(orch, st, cfg.Scan.Schedule, cfg.Scan.ScanOnStartup, log.With("component", "scheduler"))
	if err != nil {
		return err
	}
	svc := service.New(st, orch)

	handler := httpserver.New(httpserver.Handlers{
		API: api.New(svc, authn, log.With("component", "api")),
		MCP: mcpserver.New(svc, authn, version.Version),
	}, st, log)
	srv := &http.Server{
		Addr:              cfg.Server.Address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := notifier.Start(ctx); err != nil {
		return fmt.Errorf("start notifier: %w", err)
	}
	defer notifier.Close()
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := orch.Run(ctx); err != nil {
			select {
			case errc <- err:
			default:
			}
		}
	}()
	if sched != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sched.Run(ctx)
		}()
	} else {
		log.Info("scheduled scans disabled (scan.schedule is empty)")
	}
	go func() {
		log.Info("http server listening", "address", cfg.Server.Address)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errc <- err:
			default:
			}
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errc:
		log.Error("fatal error, shutting down", "error", runErr)
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	wg.Wait()
	return runErr
}

func newLogger(c config.LogConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(c.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(c.Format) == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}
