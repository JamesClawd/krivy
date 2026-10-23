// Package store persists Krivy state through GORM on SQLite or PostgreSQL.
// Callers depend on the Store interface; GormStore is the only implementation.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

// Page is offset pagination.
type Page struct {
	Limit  int
	Offset int
}

func (p Page) normalized() Page {
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

type ScanRunFilter struct {
	Status    string
	Scope     string
	Namespace string
	Page
}

type FindingFilter struct {
	Status          string // open | resolved | "" (all)
	Severity        string
	Namespace       string // findings whose image is used by an active workload in this namespace
	ImageKey        string
	VulnerabilityID string
	// Acknowledged filters by acknowledgement: nil = any.
	Acknowledged *bool
	// Deployed restricts to images still deployed: nil = any.
	Deployed *bool
	Page
}

// Summary is an aggregate view of the security state.
type Summary struct {
	OpenFindings       int64            `json:"openFindings"`
	OpenUnacknowledged int64            `json:"openUnacknowledged"`
	OpenBySeverity     map[string]int64 `json:"openBySeverity"`
	AffectedImages     int64            `json:"affectedImages"`
	DeployedImages     int64            `json:"deployedImages"`
	ActiveSilences     int64            `json:"activeSilences"`
	OpenByNamespace    map[string]int64 `json:"openByNamespace"`
	LastScan           *ScanRun         `json:"lastScan,omitempty"`
	LastSuccessfulScan *ScanRun         `json:"lastSuccessfulScan,omitempty"`
}

// Store is the repository interface used by the rest of Krivy.
type Store interface {
	// Transaction runs fn atomically with a transaction-bound Store.
	Transaction(ctx context.Context, fn func(tx Store) error) error

	CreateScanRun(ctx context.Context, r *ScanRun) error
	GetScanRun(ctx context.Context, id string) (*ScanRun, error)
	UpdateScanRun(ctx context.Context, r *ScanRun) error
	ListScanRuns(ctx context.Context, f ScanRunFilter) ([]ScanRun, int64, error)
	// ActiveScanRuns returns pending or running runs, oldest first.
	ActiveScanRuns(ctx context.Context) ([]ScanRun, error)
	// LatestScanRun returns the newest run matching scope/namespace and
	// optionally one of statuses; ErrNotFound if none.
	LatestScanRun(ctx context.Context, scope, namespace string, statuses ...string) (*ScanRun, error)

	CreateScanJobs(ctx context.Context, jobs []ScanJob) error
	ListScanJobs(ctx context.Context, runID string) ([]ScanJob, error)
	UpdateScanJob(ctx context.Context, j *ScanJob) error

	UpsertImage(ctx context.Context, img *Image) error
	GetImage(ctx context.Context, key string) (*Image, error)
	ListImages(ctx context.Context, keys []string) ([]Image, error)
	// SyncWorkloads upserts the observed workloads as active and marks
	// previously active workloads in scope (namespace, or all when "") that
	// were not observed as inactive. Images without active workloads are
	// marked not deployed.
	SyncWorkloads(ctx context.Context, namespace string, observed []Workload, now time.Time) error
	ListWorkloads(ctx context.Context, imageKeys []string, activeOnly bool) ([]Workload, error)

	GetFinding(ctx context.Context, id string) (*Finding, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int64, error)
	ListFindingsByImage(ctx context.Context, imageKey string) ([]Finding, error)
	SaveFinding(ctx context.Context, f *Finding) error

	CreateSilence(ctx context.Context, s *Silence) error
	GetSilence(ctx context.Context, id string) (*Silence, error)
	UpdateSilence(ctx context.Context, s *Silence) error
	// ListSilences returns silences; when activeAt is non-nil only those
	// active at that time.
	ListSilences(ctx context.Context, activeAt *time.Time) ([]Silence, error)

	// CreateDelivery inserts a delivery; ErrDuplicate if DedupKey exists.
	CreateDelivery(ctx context.Context, d *NotificationDelivery) error
	UpdateDelivery(ctx context.Context, d *NotificationDelivery) error
	ListDeliveries(ctx context.Context, status string, limit int) ([]NotificationDelivery, error)

	Summary(ctx context.Context) (*Summary, error)

	Ping(ctx context.Context) error
	Close() error
}

// GormStore implements Store.
type GormStore struct {
	db *gorm.DB
}

var _ Store = (*GormStore)(nil)

// Open connects to the database and runs migrations.
func Open(driver, dsn string) (*GormStore, error) {
	var dial gorm.Dialector
	switch driver {
	case "sqlite":
		dial = sqlite.Open(sqliteDSN(dsn))
	case "postgres":
		dial = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	db, err := gorm.Open(dial, &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		TranslateError:                           true,
		DisableForeignKeyConstraintWhenMigrating: true,
		NowFunc:                                  func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", driver, err)
	}
	if driver == "sqlite" {
		// SQLite allows one writer; serialize through one connection.
		sqlDB, err := db.DB()
		if err != nil {
			return nil, err
		}
		sqlDB.SetMaxOpenConns(1)
	}
	if err := Migrate(db); err != nil {
		return nil, err
	}
	return &GormStore{db: db}, nil
}

func sqliteDSN(dsn string) string {
	if strings.Contains(dsn, "_pragma") || dsn == ":memory:" {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
}

// DB exposes the underlying handle for tests.
func (s *GormStore) DB() *gorm.DB { return s.db }

func (s *GormStore) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *GormStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *GormStore) Transaction(ctx context.Context, fn func(tx Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&GormStore{db: tx})
	})
}

func (s *GormStore) q(ctx context.Context) *gorm.DB { return s.db.WithContext(ctx) }

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// --- scan runs ---

func (s *GormStore) CreateScanRun(ctx context.Context, r *ScanRun) error {
	return s.q(ctx).Create(r).Error
}

func (s *GormStore) GetScanRun(ctx context.Context, id string) (*ScanRun, error) {
	var r ScanRun
	if err := s.q(ctx).First(&r, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

func (s *GormStore) UpdateScanRun(ctx context.Context, r *ScanRun) error {
	return s.q(ctx).Save(r).Error
}

func (s *GormStore) ListScanRuns(ctx context.Context, f ScanRunFilter) ([]ScanRun, int64, error) {
	q := s.q(ctx).Model(&ScanRun{})
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.Scope != "" {
		q = q.Where("scope = ?", f.Scope)
	}
	if f.Namespace != "" {
		q = q.Where("namespace = ?", f.Namespace)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	p := f.normalized()
	var out []ScanRun
	err := q.Order("created_at DESC").Limit(p.Limit).Offset(p.Offset).Find(&out).Error
	return out, total, err
}

func (s *GormStore) ActiveScanRuns(ctx context.Context) ([]ScanRun, error) {
	var out []ScanRun
	err := s.q(ctx).Where("status IN ?", []string{StatusPending, StatusRunning}).
		Order("created_at ASC").Find(&out).Error
	return out, err
}

func (s *GormStore) LatestScanRun(ctx context.Context, scope, namespace string, statuses ...string) (*ScanRun, error) {
	q := s.q(ctx).Where("scope = ?", scope)
	if scope == ScopeNamespace {
		q = q.Where("namespace = ?", namespace)
	}
	if len(statuses) > 0 {
		q = q.Where("status IN ?", statuses)
	}
	var r ScanRun
	if err := q.Order("created_at DESC").First(&r).Error; err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

// --- scan jobs ---

func (s *GormStore) CreateScanJobs(ctx context.Context, jobs []ScanJob) error {
	if len(jobs) == 0 {
		return nil
	}
	return s.q(ctx).CreateInBatches(jobs, 100).Error
}

func (s *GormStore) ListScanJobs(ctx context.Context, runID string) ([]ScanJob, error) {
	var out []ScanJob
	err := s.q(ctx).Where("scan_run_id = ?", runID).Order("created_at ASC, image_key ASC").Find(&out).Error
	return out, err
}

func (s *GormStore) UpdateScanJob(ctx context.Context, j *ScanJob) error {
	return s.q(ctx).Save(j).Error
}

// --- images & workloads ---

func (s *GormStore) UpsertImage(ctx context.Context, img *Image) error {
	updates := clause.AssignmentColumns([]string{"repository", "digest", "ref", "last_seen_at", "deployed"})
	// Scan metadata is only overwritten when supplied, so a discovery upsert
	// (which knows neither) keeps it while a post-scan upsert persists it.
	updates = append(updates,
		clause.Assignment{Column: clause.Column{Name: "os"},
			Value: gorm.Expr("CASE WHEN excluded.os <> '' THEN excluded.os ELSE images.os END")},
		clause.Assignment{Column: clause.Column{Name: "last_scanned_at"},
			Value: gorm.Expr("COALESCE(excluded.last_scanned_at, images.last_scanned_at)")},
	)
	return s.q(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: updates,
	}).Create(img).Error
}

func (s *GormStore) GetImage(ctx context.Context, key string) (*Image, error) {
	var img Image
	if err := s.q(ctx).First(&img, "key = ?", key).Error; err != nil {
		return nil, notFound(err)
	}
	return &img, nil
}

func (s *GormStore) ListImages(ctx context.Context, keys []string) ([]Image, error) {
	var out []Image
	q := s.q(ctx)
	if keys != nil {
		if len(keys) == 0 {
			return nil, nil
		}
		q = q.Where("key IN ?", keys)
	}
	err := q.Order("key").Find(&out).Error
	return out, err
}

func (s *GormStore) SyncWorkloads(ctx context.Context, namespace string, observed []Workload, now time.Time) error {
	return s.Transaction(ctx, func(txs Store) error {
		tx := txs.(*GormStore).db
		// Deactivate everything in scope, then re-activate what we observed.
		deact := tx.Model(&Workload{}).Where("active = ?", true)
		if namespace != "" {
			deact = deact.Where("namespace = ?", namespace)
		}
		if err := deact.Update("active", false).Error; err != nil {
			return err
		}
		for i := range observed {
			w := observed[i]
			w.Active = true
			w.LastSeenAt = now
			if w.FirstSeenAt.IsZero() {
				w.FirstSeenAt = now
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "image_key"}, {Name: "namespace"}, {Name: "kind"}, {Name: "name"}, {Name: "container"}},
				DoUpdates: clause.AssignmentColumns([]string{"active", "last_seen_at"}),
			}).Create(&w).Error; err != nil {
				return err
			}
		}
		// Recompute Image.Deployed from active workloads.
		if err := tx.Model(&Image{}).Where("key NOT IN (?)",
			tx.Model(&Workload{}).Select("image_key").Where("active = ?", true)).
			Update("deployed", false).Error; err != nil {
			return err
		}
		return tx.Model(&Image{}).Where("key IN (?)",
			tx.Model(&Workload{}).Select("image_key").Where("active = ?", true)).
			Update("deployed", true).Error
	})
}

func (s *GormStore) ListWorkloads(ctx context.Context, imageKeys []string, activeOnly bool) ([]Workload, error) {
	q := s.q(ctx)
	if imageKeys != nil {
		if len(imageKeys) == 0 {
			return nil, nil
		}
		q = q.Where("image_key IN ?", imageKeys)
	}
	if activeOnly {
		q = q.Where("active = ?", true)
	}
	var out []Workload
	err := q.Order("namespace, kind, name, container").Find(&out).Error
	return out, err
}

// --- findings ---

func (s *GormStore) GetFinding(ctx context.Context, id string) (*Finding, error) {
	var f Finding
	if err := s.q(ctx).First(&f, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &f, nil
}

func (s *GormStore) findingQuery(ctx context.Context, f FindingFilter) *gorm.DB {
	q := s.q(ctx).Model(&Finding{})
	if f.Status != "" {
		q = q.Where("findings.status = ?", f.Status)
	}
	if f.Severity != "" {
		q = q.Where("findings.severity = ?", strings.ToUpper(f.Severity))
	}
	if f.ImageKey != "" {
		q = q.Where("findings.image_key = ?", f.ImageKey)
	}
	if f.VulnerabilityID != "" {
		q = q.Where("findings.vulnerability_id = ?", f.VulnerabilityID)
	}
	if f.Acknowledged != nil {
		if *f.Acknowledged {
			q = q.Where("findings.acknowledged_at IS NOT NULL")
		} else {
			q = q.Where("findings.acknowledged_at IS NULL")
		}
	}
	if f.Namespace != "" {
		q = q.Where("findings.image_key IN (?)",
			s.q(ctx).Model(&Workload{}).Select("image_key").Where("namespace = ? AND active = ?", f.Namespace, true))
	}
	if f.Deployed != nil {
		q = q.Where("findings.image_key IN (?)",
			s.q(ctx).Model(&Image{}).Select("key").Where("deployed = ?", *f.Deployed))
	}
	return q
}

func (s *GormStore) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int64, error) {
	var total int64
	if err := s.findingQuery(ctx, f).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	p := f.normalized()
	var out []Finding
	err := s.findingQuery(ctx, f).
		Order("findings.first_seen_at DESC, findings.id").
		Limit(p.Limit).Offset(p.Offset).Find(&out).Error
	return out, total, err
}

func (s *GormStore) ListFindingsByImage(ctx context.Context, imageKey string) ([]Finding, error) {
	var out []Finding
	err := s.q(ctx).Where("image_key = ?", imageKey).Order("id").Find(&out).Error
	return out, err
}

func (s *GormStore) SaveFinding(ctx context.Context, f *Finding) error {
	return s.q(ctx).Save(f).Error
}

// --- silences ---

func (s *GormStore) CreateSilence(ctx context.Context, sl *Silence) error {
	return s.q(ctx).Create(sl).Error
}

func (s *GormStore) GetSilence(ctx context.Context, id string) (*Silence, error) {
	var sl Silence
	if err := s.q(ctx).First(&sl, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &sl, nil
}

func (s *GormStore) UpdateSilence(ctx context.Context, sl *Silence) error {
	return s.q(ctx).Save(sl).Error
}

func (s *GormStore) ListSilences(ctx context.Context, activeAt *time.Time) ([]Silence, error) {
	q := s.q(ctx)
	if activeAt != nil {
		q = q.Where("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", *activeAt)
	}
	var out []Silence
	err := q.Order("created_at DESC").Find(&out).Error
	return out, err
}

// --- deliveries ---

func (s *GormStore) CreateDelivery(ctx context.Context, d *NotificationDelivery) error {
	err := s.q(ctx).Create(d).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrDuplicate
	}
	return err
}

func (s *GormStore) UpdateDelivery(ctx context.Context, d *NotificationDelivery) error {
	return s.q(ctx).Save(d).Error
}

func (s *GormStore) ListDeliveries(ctx context.Context, status string, limit int) ([]NotificationDelivery, error) {
	q := s.q(ctx)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if limit <= 0 {
		limit = 100
	}
	var out []NotificationDelivery
	err := q.Order("created_at DESC").Limit(limit).Find(&out).Error
	return out, err
}

// --- summary ---

func (s *GormStore) Summary(ctx context.Context) (*Summary, error) {
	out := &Summary{OpenBySeverity: map[string]int64{}, OpenByNamespace: map[string]int64{}}
	open := s.q(ctx).Model(&Finding{}).Where("status = ?", FindingOpen)
	if err := open.Count(&out.OpenFindings).Error; err != nil {
		return nil, err
	}
	if err := s.q(ctx).Model(&Finding{}).Where("status = ? AND acknowledged_at IS NULL", FindingOpen).
		Count(&out.OpenUnacknowledged).Error; err != nil {
		return nil, err
	}
	var sev []struct {
		Severity string
		N        int64
	}
	if err := s.q(ctx).Model(&Finding{}).Select("severity, count(*) as n").
		Where("status = ?", FindingOpen).Group("severity").Scan(&sev).Error; err != nil {
		return nil, err
	}
	for _, r := range sev {
		out.OpenBySeverity[r.Severity] = r.N
	}
	if err := s.q(ctx).Model(&Finding{}).Where("status = ?", FindingOpen).
		Distinct("image_key").Count(&out.AffectedImages).Error; err != nil {
		return nil, err
	}
	if err := s.q(ctx).Model(&Image{}).Where("deployed = ?", true).Count(&out.DeployedImages).Error; err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := s.q(ctx).Model(&Silence{}).
		Where("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", now).
		Count(&out.ActiveSilences).Error; err != nil {
		return nil, err
	}
	var ns []struct {
		Namespace string
		N         int64
	}
	if err := s.q(ctx).Table("findings").
		Select("workloads.namespace as namespace, count(distinct findings.id) as n").
		Joins("JOIN workloads ON workloads.image_key = findings.image_key AND workloads.active = ?", true).
		Where("findings.status = ?", FindingOpen).
		Group("workloads.namespace").Scan(&ns).Error; err != nil {
		return nil, err
	}
	for _, r := range ns {
		out.OpenByNamespace[r.Namespace] = r.N
	}
	var last ScanRun
	if err := s.q(ctx).Order("created_at DESC").First(&last).Error; err == nil {
		out.LastScan = &last
	}
	var lastOK ScanRun
	if err := s.q(ctx).Where("status = ?", StatusSucceeded).Order("created_at DESC").First(&lastOK).Error; err == nil {
		out.LastSuccessfulScan = &lastOK
	}
	return out, nil
}
