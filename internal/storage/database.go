// Package storage provides SQLite-based persistent storage for Falcon ToolKit.
// SQLite is the authoritative data store. Foreign keys and WAL mode are enabled.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB connection with Falcon-specific initialization.
type DB struct {
	*sql.DB
	path string
}

// Open opens or creates a Falcon SQLite database at the given path.
// The parent directory is created if it does not exist.
func Open(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Verify connection
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	db := &DB{DB: sqlDB, path: path}

	// Apply schema migrations
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("applying migrations: %w", err)
	}

	return db, nil
}

// Path returns the filesystem path to the database file.
func (db *DB) Path() string {
	return db.path
}

// BeginTx starts a new transaction.
func (db *DB) BeginTx() (*sql.Tx, error) {
	return db.Begin()
}

// CheckIntegrity runs SQLite's integrity_check pragma.
func (db *DB) CheckIntegrity() (string, error) {
	var result string
	err := db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return "", fmt.Errorf("integrity check failed: %w", err)
	}
	return result, nil
}

// CheckForeignKeys runs SQLite's foreign_key_check pragma.
func (db *DB) CheckForeignKeys() ([]ForeignKeyViolation, error) {
	rows, err := db.Query("PRAGMA foreign_key_check")
	if err != nil {
		return nil, fmt.Errorf("foreign key check failed: %w", err)
	}
	defer rows.Close()

	var violations []ForeignKeyViolation
	for rows.Next() {
		var v ForeignKeyViolation
		if err := rows.Scan(&v.Table, &v.RowID, &v.Parent, &v.FKIndex); err != nil {
			return nil, err
		}
		violations = append(violations, v)
	}
	return violations, rows.Err()
}

// ForeignKeyViolation represents a foreign key constraint violation.
type ForeignKeyViolation struct {
	Table   string
	RowID   int64
	Parent  string
	FKIndex int
}

// SchemaVersion returns the current schema version.
func (db *DB) SchemaVersion() (int, error) {
	var version int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_metadata").Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}
