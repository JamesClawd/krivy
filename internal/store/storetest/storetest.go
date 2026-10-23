// Package storetest provides database fixtures for tests. Every test using
// ForEachDriver runs against SQLite (in t.TempDir()) and, when the
// KRIVY_TEST_POSTGRES_DSN environment variable is set, against PostgreSQL in
// a fresh schema that is dropped when the test ends.
package storetest

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/l4r-s/krivy/internal/store"
)

// PostgresEnv names the environment variable holding a PostgreSQL DSN
// (URL form, e.g. postgres://user:pass@host:5432/db?sslmode=disable).
const PostgresEnv = "KRIVY_TEST_POSTGRES_DSN"

// Target is a driver plus a DSN pointing at an isolated, empty database.
type Target struct {
	Driver string
	DSN    string
}

// Targets returns an isolated target for every available driver.
func Targets(t testing.TB) []Target {
	t.Helper()
	out := []Target{SQLiteTarget(t)}
	if pg, ok := PostgresTarget(t); ok {
		out = append(out, pg)
	}
	return out
}

// SQLiteTarget returns a fresh SQLite database file in t.TempDir().
func SQLiteTarget(t testing.TB) Target {
	t.Helper()
	return Target{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "krivy.db")}
}

// PostgresTarget creates a unique schema and returns a DSN whose search_path
// points at it. ok is false when KRIVY_TEST_POSTGRES_DSN is unset.
func PostgresTarget(t testing.TB) (Target, bool) {
	t.Helper()
	base := os.Getenv(PostgresEnv)
	if base == "" {
		return Target{}, false
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "krivy_test_" + hex.EncodeToString(b[:])

	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if db, err := admin.DB(); err == nil {
			_ = db.Close()
		}
	})
	u, err := url.Parse(base)
	if err != nil || !strings.HasPrefix(u.Scheme, "postgres") {
		t.Fatalf("%s must be a postgres:// URL", PostgresEnv)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return Target{Driver: "postgres", DSN: u.String()}, true
}

// Open opens (and migrates) the target, closing it at test end.
func Open(t testing.TB, tg Target) *store.GormStore {
	t.Helper()
	st, err := store.Open(tg.Driver, tg.DSN)
	if err != nil {
		t.Fatalf("open %s: %v", tg.Driver, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// SQLite opens a fresh migrated SQLite store.
func SQLite(t testing.TB) *store.GormStore {
	t.Helper()
	return Open(t, SQLiteTarget(t))
}

// ForEachDriver runs fn as a subtest per available driver with a fresh store.
func ForEachDriver(t *testing.T, fn func(t *testing.T, st *store.GormStore)) {
	t.Helper()
	ForEachTarget(t, func(t *testing.T, tg Target) { fn(t, Open(t, tg)) })
}

// ForEachTarget runs fn as a subtest per available driver with a fresh,
// unopened target (useful for testing Open itself).
func ForEachTarget(t *testing.T, fn func(t *testing.T, tg Target)) {
	t.Helper()
	drivers := []string{"sqlite"}
	if os.Getenv(PostgresEnv) != "" {
		drivers = append(drivers, "postgres")
	}
	for _, d := range drivers {
		t.Run(d, func(t *testing.T) {
			var tg Target
			if d == "sqlite" {
				tg = SQLiteTarget(t)
			} else {
				tg, _ = PostgresTarget(t)
			}
			fn(t, tg)
		})
	}
}
