package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l4r-s/krivy/internal/config"
)

// TestWebhookExamples loads every examples/webhooks/*.yaml through the real
// config loader, builds the Engine and renders sample events to valid JSON.
func TestWebhookExamples(t *testing.T) {
	files, err := filepath.Glob("../../examples/webhooks/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 4 {
		t.Fatalf("expected at least 4 examples, found %v", files)
	}
	env := map[string]string{
		"TELEGRAM_BOT_TOKEN":  "123456:FAKE-token",
		"TELEGRAM_CHAT_ID":    "-1001234567890",
		"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/fake",
		"SLACK_WEBHOOK_URL":   "https://hooks.slack.com/services/T/B/fake",
		"ALERT_WEBHOOK_TOKEN": "fake-alert-token",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	prefix := "database:\n  driver: sqlite\n  dsn: \":memory:\"\n"
	evil := FindingInfo{
		ID: "f-evil", VulnerabilityID: "CVE-2024-9999", Severity: "CRITICAL",
		PkgName: "lib\"quote", InstalledVersion: "1\n2", Title: "</script><b>@everyone</b>   ✓",
		ImageRef: "reg.example/app:1", Namespaces: []string{"payments"}, Workloads: []string{"payments/Deployment/api"},
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(prefix+string(raw)), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			if len(cfg.Notifications.Destinations) == 0 {
				t.Fatal("no destinations")
			}
			e, err := New(cfg.Notifications, newStore(t), nil)
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			for _, d := range cfg.Notifications.Destinations {
				for _, evType := range d.Events {
					ev := sampleEvent(evType, testEvent().Time)
					if len(ev.Findings) > 0 {
						ev.Findings = append(ev.Findings, evil)
						ev.Findings[0].Namespaces = []string{"payments", "default"}
					}
					body, err := e.Render(d.Name, ev)
					if err != nil {
						t.Fatalf("%s/%s: %v", d.Name, evType, err)
					}
					if body == nil {
						t.Fatalf("%s/%s: event filtered out", d.Name, evType)
					}
					if !json.Valid(body) {
						t.Fatalf("%s/%s: invalid JSON: %s", d.Name, evType, body)
					}
					if strings.Contains(string(body), "</script>") {
						t.Errorf("%s/%s: unescaped HTML", d.Name, evType)
					}
					if strings.Contains(string(body), env["TELEGRAM_BOT_TOKEN"]) {
						t.Errorf("%s/%s: bot token leaked into body", d.Name, evType)
					}
					t.Logf("%s/%s: %s", d.Name, evType, body)
				}
			}
		})
	}
}
