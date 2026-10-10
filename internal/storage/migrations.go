package storage

import (
	"fmt"
	"time"
)

// migrate applies pending schema migrations within a transaction.
// Migration failures trigger a rollback — no partial schema state.
func (db *DB) migrate() error {
	// Ensure schema_metadata table exists first (bootstrap)
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_metadata (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_metadata: %w", err)
	}

	currentVersion, err := db.SchemaVersion()
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration %d: %w", m.Version, err)
		}

		for _, stmt := range m.Statements {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %d failed: %w\nStatement: %s", m.Version, err, stmt)
			}
		}

		_, err = tx.Exec("INSERT INTO schema_metadata (version, applied_at) VALUES (?, ?)",
			m.Version, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.Version, err)
		}
	}

	return nil
}

// Migration represents a versioned schema change.
type Migration struct {
	Version    int
	Statements []string
}

// Migrations returns the list of all migrations for informational purposes.
func (db *DB) Migrations() []Migration {
	return migrations
}

var migrations = []Migration{
	{
		Version: 1,
		Statements: []string{
			// ----- Assets -----
			`CREATE TABLE IF NOT EXISTS assets (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				hostname TEXT,
				first_observed TEXT NOT NULL,
				last_observed TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_assets_workspace ON assets(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname)`,

			// ----- Interfaces -----
			`CREATE TABLE IF NOT EXISTS interfaces (
				id TEXT PRIMARY KEY,
				asset_id TEXT NOT NULL REFERENCES assets(id),
				address TEXT NOT NULL,
				mac_address TEXT,
				network_id TEXT,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_interfaces_asset ON interfaces(asset_id)`,
			`CREATE INDEX IF NOT EXISTS idx_interfaces_address ON interfaces(address)`,
			`CREATE INDEX IF NOT EXISTS idx_interfaces_network ON interfaces(network_id)`,

			// ----- Services -----
			`CREATE TABLE IF NOT EXISTS services (
				id TEXT PRIMARY KEY,
				asset_id TEXT NOT NULL REFERENCES assets(id),
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				state TEXT NOT NULL DEFAULT 'unknown',
				service_name TEXT,
				technology TEXT,
				version TEXT,
				first_observed TEXT NOT NULL,
				last_observed TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id)`,
			`CREATE INDEX IF NOT EXISTS idx_services_port ON services(port)`,
			`CREATE INDEX IF NOT EXISTS idx_services_protocol ON services(protocol)`,

			// ----- Networks -----
			`CREATE TABLE IF NOT EXISTS networks (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				cidr TEXT NOT NULL,
				name TEXT,
				description TEXT,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_networks_workspace ON networks(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_networks_cidr ON networks(cidr)`,

			// ----- Relationships -----
			`CREATE TABLE IF NOT EXISTS relationships (
				id TEXT PRIMARY KEY,
				source_type TEXT NOT NULL,
				source_id TEXT NOT NULL,
				target_type TEXT NOT NULL,
				target_id TEXT NOT NULL,
				type TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_id)`,
			`CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_id)`,
			`CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(type)`,

			// ----- Observations -----
			`CREATE TABLE IF NOT EXISTS observations (
				id TEXT PRIMARY KEY,
				source_id TEXT NOT NULL,
				kind TEXT NOT NULL,
				raw_data TEXT NOT NULL,
				observed_at TEXT NOT NULL,
				workspace_id TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_obs_workspace ON observations(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_obs_source ON observations(source_id)`,

			// ----- Evidence -----
			`CREATE TABLE IF NOT EXISTS evidence (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				source_id TEXT NOT NULL,
				category TEXT NOT NULL DEFAULT 'direct',
				entity_type TEXT NOT NULL,
				entity_id TEXT NOT NULL,
				protocol TEXT,
				port INTEGER,
				service_name TEXT,
				technology TEXT,
				address TEXT,
				description TEXT,
				observed_at TEXT NOT NULL,
				first_observed TEXT NOT NULL,
				last_observed TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_ev_workspace ON evidence(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_ev_entity ON evidence(entity_id)`,
			`CREATE INDEX IF NOT EXISTS idx_ev_source ON evidence(source_id)`,
			`CREATE INDEX IF NOT EXISTS idx_ev_entity_type ON evidence(entity_type)`,

			// ----- Findings -----
			`CREATE TABLE IF NOT EXISTS findings (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				rule_id TEXT NOT NULL,
				category TEXT NOT NULL,
				title TEXT NOT NULL,
				description TEXT NOT NULL,
				entity_type TEXT NOT NULL,
				entity_id TEXT NOT NULL,
				evidence_ids TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'open',
				first_observed TEXT NOT NULL,
				last_observed TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_find_workspace ON findings(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_find_category ON findings(category)`,
			`CREATE INDEX IF NOT EXISTS idx_find_entity ON findings(entity_id)`,
			`CREATE INDEX IF NOT EXISTS idx_find_rule ON findings(rule_id)`,
			`CREATE INDEX IF NOT EXISTS idx_find_status ON findings(status)`,

			// ----- Assessments -----
			`CREATE TABLE IF NOT EXISTS assessments (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				ruleset_version TEXT NOT NULL,
				schema_version TEXT NOT NULL,
				total_findings INTEGER NOT NULL DEFAULT 0,
				new_findings INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_assess_workspace ON assessments(workspace_id)`,

			// ----- Assessment Snapshots -----
			`CREATE TABLE IF NOT EXISTS assessment_snapshots (
				id TEXT PRIMARY KEY,
				assessment_id TEXT NOT NULL REFERENCES assessments(id),
				workspace_id TEXT NOT NULL,
				snapshot_data TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,

			// ----- Report Snapshots -----
			`CREATE TABLE IF NOT EXISTS report_snapshots (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				format TEXT NOT NULL,
				content TEXT NOT NULL,
				fingerprint TEXT,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_report_workspace ON report_snapshots(workspace_id)`,

			// ----- Targets -----
			`CREATE TABLE IF NOT EXISTS targets (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				value TEXT NOT NULL,
				type TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_targets_workspace ON targets(workspace_id)`,

			// ----- Tags -----
			`CREATE TABLE IF NOT EXISTS tags (
				id TEXT PRIMARY KEY,
				entity_type TEXT NOT NULL,
				entity_id TEXT NOT NULL,
				name TEXT NOT NULL,
				created_at TEXT NOT NULL,
				UNIQUE(entity_type, entity_id, name)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_tags_entity ON tags(entity_type, entity_id)`,
			`CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name)`,

			// ----- Notes -----
			`CREATE TABLE IF NOT EXISTS notes (
				id TEXT PRIMARY KEY,
				entity_type TEXT NOT NULL,
				entity_id TEXT NOT NULL,
				content TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_notes_entity ON notes(entity_type, entity_id)`,

			// ----- Audit Events -----
			`CREATE TABLE IF NOT EXISTS audit_events (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				action TEXT NOT NULL,
				entity_type TEXT,
				entity_id TEXT,
				detail TEXT,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_workspace ON audit_events(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)`,

			// ----- Saved Queries -----
			`CREATE TABLE IF NOT EXISTS saved_queries (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				name TEXT NOT NULL,
				command TEXT NOT NULL,
				created_at TEXT NOT NULL,
				UNIQUE(workspace_id, name)
			)`,

			// ----- Sequences -----
			`CREATE TABLE IF NOT EXISTS sequences (
				name TEXT PRIMARY KEY,
				value INTEGER NOT NULL DEFAULT 0
			)`,

			// ----- Engagements -----
			`CREATE TABLE IF NOT EXISTS engagements (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				name TEXT NOT NULL,
				type TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				description TEXT,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_eng_workspace ON engagements(workspace_id)`,

			// ----- Objectives -----
			`CREATE TABLE IF NOT EXISTS objectives (
				id TEXT PRIMARY KEY,
				engagement_id TEXT NOT NULL REFERENCES engagements(id),
				title TEXT NOT NULL,
				completed INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_obj_engagement ON objectives(engagement_id)`,
		},
	},
	{
		Version: 2,
		Statements: []string{
			// ----- Targets Upgrade -----
			`ALTER TABLE targets ADD COLUMN input TEXT`,
			`ALTER TABLE targets ADD COLUMN normalized_value TEXT`,
			`ALTER TABLE targets ADD COLUMN scope TEXT NOT NULL DEFAULT 'in_scope'`,
			`ALTER TABLE targets ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'`,
			`ALTER TABLE targets ADD COLUMN updated_at TEXT`,
			`ALTER TABLE targets ADD COLUMN metadata TEXT`,
			`UPDATE targets SET input = value, normalized_value = value, updated_at = created_at WHERE input IS NULL`,
			`CREATE INDEX IF NOT EXISTS idx_targets_norm ON targets(normalized_value)`,
			`CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)`,
			`CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type)`,

			// ----- Scope Rules -----
			`CREATE TABLE IF NOT EXISTS scope_rules (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				rule_type TEXT NOT NULL,
				target_type TEXT NOT NULL,
				pattern TEXT NOT NULL,
				description TEXT,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_scope_workspace ON scope_rules(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_scope_type ON scope_rules(rule_type)`,

			// ----- Evidence Confidence Column -----
			`ALTER TABLE evidence ADD COLUMN confidence TEXT NOT NULL DEFAULT 'OBSERVED'`,
		},
	},
	{
		Version: 3,
		Statements: []string{
			// ----- Assessment Runs -----
			`CREATE TABLE IF NOT EXISTS assessment_runs (
				id TEXT PRIMARY KEY,
				workspace_id TEXT NOT NULL,
				target_id TEXT,
				target_value TEXT,
				plan_json TEXT,
				status TEXT NOT NULL,
				started_at TEXT NOT NULL,
				completed_at TEXT,
				collector_stats TEXT,
				errors TEXT,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_runs_workspace ON assessment_runs(workspace_id)`,
			`CREATE INDEX IF NOT EXISTS idx_runs_status ON assessment_runs(status)`,
		},
	},
}
