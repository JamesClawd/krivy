package store

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// schemaMigration records applied migration versions.
type schemaMigration struct {
	Version   int `gorm:"primaryKey;autoIncrement:false"`
	Name      string
	AppliedAt time.Time
}

type migration struct {
	Version int
	Name    string
	Up      func(tx *gorm.DB) error
}

// migrations are applied in order; never edit or reorder an applied entry,
// append a new one instead.
var migrations = []migration{
	{1, "initial schema", func(tx *gorm.DB) error {
		return tx.AutoMigrate(AllModels()...)
	}},
}

// SchemaVersion is the latest migration version.
func SchemaVersion() int { return migrations[len(migrations)-1].Version }

// Migrate applies pending migrations transactionally.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&schemaMigration{}); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	var applied []schemaMigration
	if err := db.Find(&applied).Error; err != nil {
		return err
	}
	done := map[int]bool{}
	for _, m := range applied {
		done[m.Version] = true
	}
	for _, m := range migrations {
		if done[m.Version] {
			continue
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := m.Up(tx); err != nil {
				return err
			}
			return tx.Create(&schemaMigration{Version: m.Version, Name: m.Name, AppliedAt: time.Now().UTC()}).Error
		})
		if err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
	}
	return nil
}
