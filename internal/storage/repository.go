package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// -------------------------------------------------------------------
// Sequences
// -------------------------------------------------------------------

// NextSequence atomically increments and returns the next value for a named sequence.
func (db *DB) NextSequence(tx *sql.Tx, name string) (int, error) {
	exec := func(query string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.Exec(query, args...)
		}
		return db.Exec(query, args...)
	}
	queryRow := func(query string, args ...interface{}) *sql.Row {
		if tx != nil {
			return tx.QueryRow(query, args...)
		}
		return db.QueryRow(query, args...)
	}

	_, err := exec("INSERT OR IGNORE INTO sequences (name, value) VALUES (?, 0)", name)
	if err != nil {
		return 0, err
	}
	_, err = exec("UPDATE sequences SET value = value + 1 WHERE name = ?", name)
	if err != nil {
		return 0, err
	}
	var val int
	err = queryRow("SELECT value FROM sequences WHERE name = ?", name).Scan(&val)
	return val, err
}

// -------------------------------------------------------------------
// Assets
// -------------------------------------------------------------------

// InsertAsset inserts a new asset record.
func (db *DB) InsertAsset(tx *sql.Tx, a *domain.Asset) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = time.Now().UTC()
	}
	query := `INSERT INTO assets (id, workspace_id, hostname, first_observed, last_observed, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{a.ID, a.WorkspaceID, a.Hostname,
		a.FirstObserved.Format(time.RFC3339), a.LastObserved.Format(time.RFC3339),
		now, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// GetAsset retrieves an asset by ID.
func (db *DB) GetAsset(id string) (*domain.Asset, error) {
	a := &domain.Asset{}
	var firstObs, lastObs, created, updated string
	err := db.QueryRow(`SELECT id, workspace_id, hostname, first_observed, last_observed, created_at, updated_at
		FROM assets WHERE id = ?`, id).Scan(&a.ID, &a.WorkspaceID, &a.Hostname, &firstObs, &lastObs, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
	a.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	a.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return a, nil
}

// ListAssets returns all assets for a workspace.
func (db *DB) ListAssets(workspaceID string) ([]*domain.Asset, error) {
	rows, err := db.Query(`SELECT id, workspace_id, hostname, first_observed, last_observed, created_at, updated_at
		FROM assets WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*domain.Asset
	for rows.Next() {
		a := &domain.Asset{}
		var firstObs, lastObs, created, updated string
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.Hostname, &firstObs, &lastObs, &created, &updated); err != nil {
			return nil, err
		}
		a.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		a.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		a.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// CountAssets returns the number of assets in a workspace.
func (db *DB) CountAssets(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM assets WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

// SearchAssets searches assets by hostname or ID containing query.
func (db *DB) SearchAssets(workspaceID, query string) ([]*domain.Asset, error) {
	q := "%" + query + "%"
	rows, err := db.Query(`SELECT id, workspace_id, hostname, first_observed, last_observed, created_at, updated_at
		FROM assets WHERE workspace_id = ? AND (id LIKE ? OR hostname LIKE ?) ORDER BY id`, workspaceID, q, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*domain.Asset
	for rows.Next() {
		a := &domain.Asset{}
		var firstObs, lastObs, created, updated string
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.Hostname, &firstObs, &lastObs, &created, &updated); err != nil {
			return nil, err
		}
		a.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		a.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		a.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// -------------------------------------------------------------------
// Interfaces
// -------------------------------------------------------------------

// InsertInterface inserts a new interface record.
func (db *DB) InsertInterface(tx *sql.Tx, i *domain.Interface) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO interfaces (id, asset_id, address, mac_address, network_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{i.ID, i.AssetID, i.Address, i.MACAddress, i.NetworkID, now, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListInterfaces returns all interfaces for a workspace (via asset join).
func (db *DB) ListInterfaces(workspaceID string) ([]*domain.Interface, error) {
	rows, err := db.Query(`SELECT i.id, i.asset_id, i.address, i.mac_address, i.network_id, i.created_at, i.updated_at
		FROM interfaces i JOIN assets a ON i.asset_id = a.id WHERE a.workspace_id = ? ORDER BY i.id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ifaces []*domain.Interface
	for rows.Next() {
		ifc := &domain.Interface{}
		var created, updated string
		var mac, netID sql.NullString
		if err := rows.Scan(&ifc.ID, &ifc.AssetID, &ifc.Address, &mac, &netID, &created, &updated); err != nil {
			return nil, err
		}
		ifc.MACAddress = mac.String
		ifc.NetworkID = netID.String
		ifc.CreatedAt, _ = time.Parse(time.RFC3339, created)
		ifc.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		ifaces = append(ifaces, ifc)
	}
	return ifaces, rows.Err()
}

// ListInterfacesByAsset returns all interfaces belonging to an asset.
func (db *DB) ListInterfacesByAsset(assetID string) ([]*domain.Interface, error) {
	rows, err := db.Query(`SELECT id, asset_id, address, mac_address, network_id, created_at, updated_at
		FROM interfaces WHERE asset_id = ? ORDER BY id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ifaces []*domain.Interface
	for rows.Next() {
		ifc := &domain.Interface{}
		var created, updated string
		var mac, netID sql.NullString
		if err := rows.Scan(&ifc.ID, &ifc.AssetID, &ifc.Address, &mac, &netID, &created, &updated); err != nil {
			return nil, err
		}
		ifc.MACAddress = mac.String
		ifc.NetworkID = netID.String
		ifc.CreatedAt, _ = time.Parse(time.RFC3339, created)
		ifc.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		ifaces = append(ifaces, ifc)
	}
	return ifaces, rows.Err()
}

// CountInterfaces returns the number of interfaces in a workspace.
func (db *DB) CountInterfaces(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM interfaces i JOIN assets a ON i.asset_id = a.id WHERE a.workspace_id = ?`, workspaceID).Scan(&count)
	return count, err
}

// FindInterfaceByAddress finds an interface by IP address within a workspace.
func (db *DB) FindInterfaceByAddress(workspaceID, address string) (*domain.Interface, error) {
	ifc := &domain.Interface{}
	var created, updated string
	var mac, netID sql.NullString
	err := db.QueryRow(`SELECT i.id, i.asset_id, i.address, i.mac_address, i.network_id, i.created_at, i.updated_at
		FROM interfaces i JOIN assets a ON i.asset_id = a.id
		WHERE a.workspace_id = ? AND i.address = ?`, workspaceID, address).
		Scan(&ifc.ID, &ifc.AssetID, &ifc.Address, &mac, &netID, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ifc.MACAddress = mac.String
	ifc.NetworkID = netID.String
	ifc.CreatedAt, _ = time.Parse(time.RFC3339, created)
	ifc.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return ifc, nil
}

// -------------------------------------------------------------------
// Services
// -------------------------------------------------------------------

// InsertService inserts a new service record.
func (db *DB) InsertService(tx *sql.Tx, s *domain.Service) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO services (id, asset_id, protocol, port, state, service_name, technology, version,
		first_observed, last_observed, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{s.ID, s.AssetID, s.Protocol, s.Port, string(s.State), s.ServiceName, s.Technology, s.Version,
		s.FirstObserved.Format(time.RFC3339), s.LastObserved.Format(time.RFC3339), now, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListServices returns all services for a workspace.
func (db *DB) ListServices(workspaceID string) ([]*domain.Service, error) {
	rows, err := db.Query(`SELECT s.id, s.asset_id, s.protocol, s.port, s.state, s.service_name, s.technology, s.version,
		s.first_observed, s.last_observed, s.created_at, s.updated_at
		FROM services s JOIN assets a ON s.asset_id = a.id WHERE a.workspace_id = ? ORDER BY s.id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServices(rows)
}

// ListServicesByAsset returns all services for a specific asset.
func (db *DB) ListServicesByAsset(assetID string) ([]*domain.Service, error) {
	rows, err := db.Query(`SELECT id, asset_id, protocol, port, state, service_name, technology, version,
		first_observed, last_observed, created_at, updated_at
		FROM services WHERE asset_id = ? ORDER BY port`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServices(rows)
}

// ListServicesByPort returns services matching a port number.
func (db *DB) ListServicesByPort(workspaceID string, port int) ([]*domain.Service, error) {
	rows, err := db.Query(`SELECT s.id, s.asset_id, s.protocol, s.port, s.state, s.service_name, s.technology, s.version,
		s.first_observed, s.last_observed, s.created_at, s.updated_at
		FROM services s JOIN assets a ON s.asset_id = a.id WHERE a.workspace_id = ? AND s.port = ? ORDER BY s.id`, workspaceID, port)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServices(rows)
}

// ListServicesByProtocol returns services matching a protocol.
func (db *DB) ListServicesByProtocol(workspaceID, protocol string) ([]*domain.Service, error) {
	rows, err := db.Query(`SELECT s.id, s.asset_id, s.protocol, s.port, s.state, s.service_name, s.technology, s.version,
		s.first_observed, s.last_observed, s.created_at, s.updated_at
		FROM services s JOIN assets a ON s.asset_id = a.id WHERE a.workspace_id = ? AND s.protocol = ? ORDER BY s.id`, workspaceID, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServices(rows)
}

// CountServices returns the number of services in a workspace.
func (db *DB) CountServices(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM services s JOIN assets a ON s.asset_id = a.id WHERE a.workspace_id = ?`, workspaceID).Scan(&count)
	return count, err
}

// FindService finds a service by asset, protocol, and port.
func (db *DB) FindService(assetID, protocol string, port int) (*domain.Service, error) {
	s := &domain.Service{}
	var state, firstObs, lastObs, created, updated string
	var svcName, tech, ver sql.NullString
	err := db.QueryRow(`SELECT id, asset_id, protocol, port, state, service_name, technology, version,
		first_observed, last_observed, created_at, updated_at
		FROM services WHERE asset_id = ? AND protocol = ? AND port = ?`, assetID, protocol, port).
		Scan(&s.ID, &s.AssetID, &s.Protocol, &s.Port, &state, &svcName, &tech, &ver,
			&firstObs, &lastObs, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.State = domain.ServiceState(state)
	s.ServiceName = svcName.String
	s.Technology = tech.String
	s.Version = ver.String
	s.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
	s.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return s, nil
}

func scanServices(rows *sql.Rows) ([]*domain.Service, error) {
	var services []*domain.Service
	for rows.Next() {
		s := &domain.Service{}
		var state, firstObs, lastObs, created, updated string
		var svcName, tech, ver sql.NullString
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Protocol, &s.Port, &state, &svcName, &tech, &ver,
			&firstObs, &lastObs, &created, &updated); err != nil {
			return nil, err
		}
		s.State = domain.ServiceState(state)
		s.ServiceName = svcName.String
		s.Technology = tech.String
		s.Version = ver.String
		s.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		s.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		s.CreatedAt, _ = time.Parse(time.RFC3339, created)
		s.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		services = append(services, s)
	}
	return services, rows.Err()
}

// -------------------------------------------------------------------
// Networks
// -------------------------------------------------------------------

// InsertNetwork inserts a new network record.
func (db *DB) InsertNetwork(tx *sql.Tx, n *domain.Network) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO networks (id, workspace_id, cidr, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{n.ID, n.WorkspaceID, n.CIDR, n.Name, n.Description, now, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListNetworks returns all networks for a workspace.
func (db *DB) ListNetworks(workspaceID string) ([]*domain.Network, error) {
	rows, err := db.Query(`SELECT id, workspace_id, cidr, name, description, created_at, updated_at
		FROM networks WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []*domain.Network
	for rows.Next() {
		n := &domain.Network{}
		var created, updated string
		var name, desc sql.NullString
		if err := rows.Scan(&n.ID, &n.WorkspaceID, &n.CIDR, &name, &desc, &created, &updated); err != nil {
			return nil, err
		}
		n.Name = name.String
		n.Description = desc.String
		n.CreatedAt, _ = time.Parse(time.RFC3339, created)
		n.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		networks = append(networks, n)
	}
	return networks, rows.Err()
}

// GetNetwork retrieves a network by ID.
func (db *DB) GetNetwork(id string) (*domain.Network, error) {
	n := &domain.Network{}
	var created, updated string
	var name, desc sql.NullString
	err := db.QueryRow(`SELECT id, workspace_id, cidr, name, description, created_at, updated_at
		FROM networks WHERE id = ?`, id).Scan(&n.ID, &n.WorkspaceID, &n.CIDR, &name, &desc, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.Name = name.String
	n.Description = desc.String
	n.CreatedAt, _ = time.Parse(time.RFC3339, created)
	n.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return n, nil
}

// FindNetworkByCIDR finds a network by its CIDR in a workspace.
func (db *DB) FindNetworkByCIDR(workspaceID, cidr string) (*domain.Network, error) {
	n := &domain.Network{}
	var created, updated string
	var name, desc sql.NullString
	err := db.QueryRow(`SELECT id, workspace_id, cidr, name, description, created_at, updated_at
		FROM networks WHERE workspace_id = ? AND cidr = ?`, workspaceID, cidr).
		Scan(&n.ID, &n.WorkspaceID, &n.CIDR, &name, &desc, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.Name = name.String
	n.Description = desc.String
	n.CreatedAt, _ = time.Parse(time.RFC3339, created)
	n.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return n, nil
}

// CountNetworks returns the number of networks in a workspace.
func (db *DB) CountNetworks(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM networks WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

// -------------------------------------------------------------------
// Relationships
// -------------------------------------------------------------------

// InsertRelationship inserts a new relationship record.
func (db *DB) InsertRelationship(tx *sql.Tx, r *domain.Relationship) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO relationships (id, source_type, source_id, target_type, target_id, type, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{r.ID, r.SourceType, r.SourceID, r.TargetType, r.TargetID, string(r.Type), now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListRelationships returns all relationships in a workspace (approximated via source entities).
func (db *DB) ListRelationships(workspaceID string) ([]*domain.Relationship, error) {
	// Relationships link entities within a workspace. We load all of them
	// since they're already scoped by the entities they reference.
	rows, err := db.Query(`SELECT id, source_type, source_id, target_type, target_id, type, created_at
		FROM relationships ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rels []*domain.Relationship
	for rows.Next() {
		r := &domain.Relationship{}
		var relType, created string
		if err := rows.Scan(&r.ID, &r.SourceType, &r.SourceID, &r.TargetType, &r.TargetID, &relType, &created); err != nil {
			return nil, err
		}
		r.Type = domain.RelationshipType(relType)
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		rels = append(rels, r)
	}
	return rels, rows.Err()
}

// CountRelationships returns the number of relationships.
func (db *DB) CountRelationships() (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM relationships").Scan(&count)
	return count, err
}

// -------------------------------------------------------------------
// Observations
// -------------------------------------------------------------------

// InsertObservation inserts a new observation record.
func (db *DB) InsertObservation(tx *sql.Tx, o *domain.Observation) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO observations (id, source_id, kind, raw_data, observed_at, workspace_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{o.ID, o.SourceID, string(o.Kind), o.RawData, o.ObservedAt.Format(time.RFC3339), o.WorkspaceID, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// CountObservations returns the number of observations in a workspace.
func (db *DB) CountObservations(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM observations WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

// -------------------------------------------------------------------
// Evidence
// -------------------------------------------------------------------

// InsertEvidence inserts a new evidence record.
func (db *DB) InsertEvidence(tx *sql.Tx, e *domain.Evidence) error {
	now := time.Now().UTC().Format(time.RFC3339)
	conf := string(e.Confidence)
	if conf == "" {
		conf = string(domain.ConfObserved)
	}
	query := `INSERT INTO evidence (id, workspace_id, source_id, category, confidence, entity_type, entity_id, protocol, port,
		service_name, technology, address, description, observed_at, first_observed, last_observed, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{e.ID, e.WorkspaceID, e.SourceID, string(e.Category), conf, e.EntityType, e.EntityID,
		e.Protocol, e.Port, e.ServiceName, e.Technology, e.Address, e.Description,
		e.ObservedAt.Format(time.RFC3339), e.FirstObserved.Format(time.RFC3339), e.LastObserved.Format(time.RFC3339), now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// GetEvidence retrieves an evidence record by ID.
func (db *DB) GetEvidence(id string) (*domain.Evidence, error) {
	e := &domain.Evidence{}
	var category, conf, obsAt, firstObs, lastObs, created string
	var proto, svcName, tech, addr, desc sql.NullString
	var port sql.NullInt64
	err := db.QueryRow(`SELECT id, workspace_id, source_id, category, COALESCE(confidence, 'OBSERVED'), entity_type, entity_id, protocol, port,
		service_name, technology, address, description, observed_at, first_observed, last_observed, created_at
		FROM evidence WHERE id = ?`, id).
		Scan(&e.ID, &e.WorkspaceID, &e.SourceID, &category, &conf, &e.EntityType, &e.EntityID,
			&proto, &port, &svcName, &tech, &addr, &desc, &obsAt, &firstObs, &lastObs, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Category = domain.EvidenceCategory(category)
	e.Confidence = domain.ConfidenceLevel(conf)
	e.Protocol = proto.String
	e.Port = int(port.Int64)
	e.ServiceName = svcName.String
	e.Technology = tech.String
	e.Address = addr.String
	e.Description = desc.String
	e.ObservedAt, _ = time.Parse(time.RFC3339, obsAt)
	e.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
	e.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
	e.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return e, nil
}

// ListEvidence returns all evidence for a workspace.
func (db *DB) ListEvidence(workspaceID string) ([]*domain.Evidence, error) {
	rows, err := db.Query(`SELECT id, workspace_id, source_id, category, COALESCE(confidence, 'OBSERVED'), entity_type, entity_id, protocol, port,
		service_name, technology, address, description, observed_at, first_observed, last_observed, created_at
		FROM evidence WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvidence(rows)
}

// ListEvidenceByEntity returns evidence linked to a specific entity.
func (db *DB) ListEvidenceByEntity(entityID string) ([]*domain.Evidence, error) {
	rows, err := db.Query(`SELECT id, workspace_id, source_id, category, COALESCE(confidence, 'OBSERVED'), entity_type, entity_id, protocol, port,
		service_name, technology, address, description, observed_at, first_observed, last_observed, created_at
		FROM evidence WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvidence(rows)
}

// ListEvidenceBySource returns evidence from a specific source.
func (db *DB) ListEvidenceBySource(workspaceID, sourceID string) ([]*domain.Evidence, error) {
	rows, err := db.Query(`SELECT id, workspace_id, source_id, category, COALESCE(confidence, 'OBSERVED'), entity_type, entity_id, protocol, port,
		service_name, technology, address, description, observed_at, first_observed, last_observed, created_at
		FROM evidence WHERE workspace_id = ? AND source_id = ? ORDER BY id`, workspaceID, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvidence(rows)
}

// CountEvidence returns the number of evidence records in a workspace.
func (db *DB) CountEvidence(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM evidence WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

func scanEvidence(rows *sql.Rows) ([]*domain.Evidence, error) {
	var evidence []*domain.Evidence
	for rows.Next() {
		e := &domain.Evidence{}
		var category, conf, obsAt, firstObs, lastObs, created string
		var proto, svcName, tech, addr, desc sql.NullString
		var port sql.NullInt64
		if err := rows.Scan(&e.ID, &e.WorkspaceID, &e.SourceID, &category, &conf, &e.EntityType, &e.EntityID,
			&proto, &port, &svcName, &tech, &addr, &desc, &obsAt, &firstObs, &lastObs, &created); err != nil {
			return nil, err
		}
		e.Category = domain.EvidenceCategory(category)
		e.Confidence = domain.ConfidenceLevel(conf)
		e.Protocol = proto.String
		e.Port = int(port.Int64)
		e.ServiceName = svcName.String
		e.Technology = tech.String
		e.Address = addr.String
		e.Description = desc.String
		e.ObservedAt, _ = time.Parse(time.RFC3339, obsAt)
		e.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		e.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		e.CreatedAt, _ = time.Parse(time.RFC3339, created)
		evidence = append(evidence, e)
	}
	return evidence, rows.Err()
}

// -------------------------------------------------------------------
// Findings
// -------------------------------------------------------------------

// InsertFinding inserts or updates a finding record.
func (db *DB) InsertFinding(tx *sql.Tx, f *domain.Finding) error {
	now := time.Now().UTC().Format(time.RFC3339)
	evidenceJSON, _ := json.Marshal(f.EvidenceIDs)
	query := `INSERT INTO findings (id, workspace_id, rule_id, category, title, description, entity_type, entity_id,
		evidence_ids, status, first_observed, last_observed, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{f.ID, f.WorkspaceID, f.RuleID, string(f.Category), f.Title, f.Description,
		f.EntityType, f.EntityID, string(evidenceJSON), string(f.Status),
		f.FirstObserved.Format(time.RFC3339), f.LastObserved.Format(time.RFC3339), now, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// GetFinding retrieves a finding by ID.
func (db *DB) GetFinding(id string) (*domain.Finding, error) {
	f := &domain.Finding{}
	var category, status, evIDs, firstObs, lastObs, created, updated string
	err := db.QueryRow(`SELECT id, workspace_id, rule_id, category, title, description, entity_type, entity_id,
		evidence_ids, status, first_observed, last_observed, created_at, updated_at
		FROM findings WHERE id = ?`, id).
		Scan(&f.ID, &f.WorkspaceID, &f.RuleID, &category, &f.Title, &f.Description,
			&f.EntityType, &f.EntityID, &evIDs, &status, &firstObs, &lastObs, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Category = domain.FindingCategory(category)
	f.Status = domain.FindingStatus(status)
	json.Unmarshal([]byte(evIDs), &f.EvidenceIDs)
	f.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
	f.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
	f.CreatedAt, _ = time.Parse(time.RFC3339, created)
	f.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return f, nil
}

// ListFindings returns all findings for a workspace.
func (db *DB) ListFindings(workspaceID string) ([]*domain.Finding, error) {
	rows, err := db.Query(`SELECT id, workspace_id, rule_id, category, title, description, entity_type, entity_id,
		evidence_ids, status, first_observed, last_observed, created_at, updated_at
		FROM findings WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// ListFindingsByCategory returns findings filtered by category.
func (db *DB) ListFindingsByCategory(workspaceID string, category domain.FindingCategory) ([]*domain.Finding, error) {
	rows, err := db.Query(`SELECT id, workspace_id, rule_id, category, title, description, entity_type, entity_id,
		evidence_ids, status, first_observed, last_observed, created_at, updated_at
		FROM findings WHERE workspace_id = ? AND category = ? ORDER BY id`, workspaceID, string(category))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// ListFindingsByEntity returns findings related to a specific entity.
func (db *DB) ListFindingsByEntity(workspaceID, entityID string) ([]*domain.Finding, error) {
	rows, err := db.Query(`SELECT id, workspace_id, rule_id, category, title, description, entity_type, entity_id,
		evidence_ids, status, first_observed, last_observed, created_at, updated_at
		FROM findings WHERE workspace_id = ? AND entity_id = ? ORDER BY id`, workspaceID, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// CountFindings returns the number of findings in a workspace.
func (db *DB) CountFindings(workspaceID string) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM findings WHERE workspace_id = ?", workspaceID).Scan(&count)
	return count, err
}

// UpdateFindingStatus updates the status of a finding.
func (db *DB) UpdateFindingStatus(id string, status domain.FindingStatus) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?", string(status), now, id)
	return err
}

// DeleteFindingsByWorkspace removes all findings for a workspace (used before reassessment).
func (db *DB) DeleteFindingsByWorkspace(tx *sql.Tx, workspaceID string) error {
	query := "DELETE FROM findings WHERE workspace_id = ?"
	if tx != nil {
		_, err := tx.Exec(query, workspaceID)
		return err
	}
	_, err := db.Exec(query, workspaceID)
	return err
}

func scanFindings(rows *sql.Rows) ([]*domain.Finding, error) {
	var findings []*domain.Finding
	for rows.Next() {
		f := &domain.Finding{}
		var category, status, evIDs, firstObs, lastObs, created, updated string
		if err := rows.Scan(&f.ID, &f.WorkspaceID, &f.RuleID, &category, &f.Title, &f.Description,
			&f.EntityType, &f.EntityID, &evIDs, &status, &firstObs, &lastObs, &created, &updated); err != nil {
			return nil, err
		}
		f.Category = domain.FindingCategory(category)
		f.Status = domain.FindingStatus(status)
		json.Unmarshal([]byte(evIDs), &f.EvidenceIDs)
		f.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		f.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		f.CreatedAt, _ = time.Parse(time.RFC3339, created)
		f.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// -------------------------------------------------------------------
// Assessments
// -------------------------------------------------------------------

// InsertAssessment inserts a new assessment record.
func (db *DB) InsertAssessment(tx *sql.Tx, a *domain.Assessment) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO assessments (id, workspace_id, ruleset_version, schema_version, total_findings, new_findings, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{a.ID, a.WorkspaceID, a.RulesetVersion, a.SchemaVersion, a.TotalFindings, a.NewFindings, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListAssessments returns all assessments for a workspace.
func (db *DB) ListAssessments(workspaceID string) ([]*domain.Assessment, error) {
	rows, err := db.Query(`SELECT id, workspace_id, ruleset_version, schema_version, total_findings, new_findings, created_at
		FROM assessments WHERE workspace_id = ? ORDER BY created_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assessments []*domain.Assessment
	for rows.Next() {
		a := &domain.Assessment{}
		var created string
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.RulesetVersion, &a.SchemaVersion,
			&a.TotalFindings, &a.NewFindings, &created); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		assessments = append(assessments, a)
	}
	return assessments, rows.Err()
}

// -------------------------------------------------------------------
// Assessment Snapshots
// -------------------------------------------------------------------

// InsertAssessmentSnapshot inserts a snapshot.
func (db *DB) InsertAssessmentSnapshot(tx *sql.Tx, s *domain.AssessmentSnapshot) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO assessment_snapshots (id, assessment_id, workspace_id, snapshot_data, created_at)
		VALUES (?, ?, ?, ?, ?)`
	args := []interface{}{s.ID, s.AssessmentID, s.WorkspaceID, s.SnapshotData, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// -------------------------------------------------------------------
// Report Snapshots
// -------------------------------------------------------------------

// InsertReportSnapshot inserts a report snapshot.
func (db *DB) InsertReportSnapshot(tx *sql.Tx, r *domain.ReportSnapshot) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO report_snapshots (id, workspace_id, format, content, fingerprint, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	args := []interface{}{r.ID, r.WorkspaceID, r.Format, r.Content, r.Fingerprint, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListReportSnapshots returns all report snapshots for a workspace.
func (db *DB) ListReportSnapshots(workspaceID string) ([]*domain.ReportSnapshot, error) {
	rows, err := db.Query(`SELECT id, workspace_id, format, content, fingerprint, created_at
		FROM report_snapshots WHERE workspace_id = ? ORDER BY created_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []*domain.ReportSnapshot
	for rows.Next() {
		r := &domain.ReportSnapshot{}
		var created string
		var fp sql.NullString
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &r.Format, &r.Content, &fp, &created); err != nil {
			return nil, err
		}
		r.Fingerprint = fp.String
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

// -------------------------------------------------------------------
// Targets
// -------------------------------------------------------------------

// InsertTarget inserts a new target record.
func (db *DB) InsertTarget(tx *sql.Tx, t *domain.Target) error {
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = t.CreatedAt
	}
	if t.Value == "" && t.NormalizedValue != "" {
		t.Value = t.NormalizedValue
	}
	if t.NormalizedValue == "" && t.Value != "" {
		t.NormalizedValue = t.Value
	}
	if t.Input == "" {
		t.Input = t.NormalizedValue
	}
	if t.Scope == "" {
		t.Scope = domain.TargetInScope
	}
	if t.Status == "" {
		t.Status = domain.TargetStatusPending
	}

	var metaJSON sql.NullString
	if len(t.Metadata) > 0 {
		b, err := json.Marshal(t.Metadata)
		if err == nil {
			metaJSON = sql.NullString{String: string(b), Valid: true}
		}
	}

	query := `INSERT INTO targets (id, workspace_id, input, normalized_value, value, type, scope, status, updated_at, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{
		t.ID,
		t.WorkspaceID,
		t.Input,
		t.NormalizedValue,
		t.Value,
		string(t.Type),
		string(t.Scope),
		string(t.Status),
		t.UpdatedAt.Format(time.RFC3339),
		metaJSON,
		t.CreatedAt.Format(time.RFC3339),
	}

	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// UpdateTarget updates an existing target record.
func (db *DB) UpdateTarget(tx *sql.Tx, t *domain.Target) error {
	t.UpdatedAt = time.Now().UTC()
	if t.Value == "" && t.NormalizedValue != "" {
		t.Value = t.NormalizedValue
	}
	var metaJSON sql.NullString
	if len(t.Metadata) > 0 {
		b, err := json.Marshal(t.Metadata)
		if err == nil {
			metaJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	query := `UPDATE targets SET input = ?, normalized_value = ?, value = ?, type = ?, scope = ?, status = ?, updated_at = ?, metadata = ?
		WHERE id = ?`
	args := []interface{}{
		t.Input,
		t.NormalizedValue,
		t.Value,
		string(t.Type),
		string(t.Scope),
		string(t.Status),
		t.UpdatedAt.Format(time.RFC3339),
		metaJSON,
		t.ID,
	}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// GetTarget retrieves a target by ID.
func (db *DB) GetTarget(id string) (*domain.Target, error) {
	t := &domain.Target{}
	var tType, scopeVal, statusVal, created, updated string
	var inputVal, normVal, val sql.NullString
	var metaJSON sql.NullString

	err := db.QueryRow(`SELECT id, workspace_id, COALESCE(input, value), COALESCE(normalized_value, value), value,
		type, COALESCE(scope, 'in_scope'), COALESCE(status, 'pending'), COALESCE(updated_at, created_at), metadata, created_at
		FROM targets WHERE id = ?`, id).
		Scan(&t.ID, &t.WorkspaceID, &inputVal, &normVal, &val, &tType, &scopeVal, &statusVal, &updated, &metaJSON, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.Input = inputVal.String
	t.NormalizedValue = normVal.String
	t.Value = val.String
	t.Type = domain.TargetType(tType)
	t.Scope = domain.TargetScope(scopeVal)
	t.Status = domain.TargetStatus(statusVal)
	t.CreatedAt, _ = time.Parse(time.RFC3339, created)
	t.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	if metaJSON.Valid && metaJSON.String != "" {
		_ = json.Unmarshal([]byte(metaJSON.String), &t.Metadata)
	}
	return t, nil
}

// GetTargetByNormalizedValue retrieves a target by normalized value in a workspace.
func (db *DB) GetTargetByNormalizedValue(workspaceID, normVal string) (*domain.Target, error) {
	t := &domain.Target{}
	var tType, scopeVal, statusVal, created, updated string
	var inputVal, nVal, val sql.NullString
	var metaJSON sql.NullString

	err := db.QueryRow(`SELECT id, workspace_id, COALESCE(input, value), COALESCE(normalized_value, value), value,
		type, COALESCE(scope, 'in_scope'), COALESCE(status, 'pending'), COALESCE(updated_at, created_at), metadata, created_at
		FROM targets WHERE workspace_id = ? AND (normalized_value = ? OR value = ?) LIMIT 1`, workspaceID, normVal, normVal).
		Scan(&t.ID, &t.WorkspaceID, &inputVal, &nVal, &val, &tType, &scopeVal, &statusVal, &updated, &metaJSON, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	t.Input = inputVal.String
	t.NormalizedValue = nVal.String
	t.Value = val.String
	t.Type = domain.TargetType(tType)
	t.Scope = domain.TargetScope(scopeVal)
	t.Status = domain.TargetStatus(statusVal)
	t.CreatedAt, _ = time.Parse(time.RFC3339, created)
	t.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	if metaJSON.Valid && metaJSON.String != "" {
		_ = json.Unmarshal([]byte(metaJSON.String), &t.Metadata)
	}
	return t, nil
}

// ListTargets returns all targets for a workspace.
func (db *DB) ListTargets(workspaceID string) ([]*domain.Target, error) {
	rows, err := db.Query(`SELECT id, workspace_id, COALESCE(input, value), COALESCE(normalized_value, value), value,
		type, COALESCE(scope, 'in_scope'), COALESCE(status, 'pending'), COALESCE(updated_at, created_at), metadata, created_at
		FROM targets WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*domain.Target
	for rows.Next() {
		t := &domain.Target{}
		var tType, scopeVal, statusVal, created, updated string
		var inputVal, normVal, val sql.NullString
		var metaJSON sql.NullString
		if err := rows.Scan(&t.ID, &t.WorkspaceID, &inputVal, &normVal, &val, &tType, &scopeVal, &statusVal, &updated, &metaJSON, &created); err != nil {
			return nil, err
		}
		t.Input = inputVal.String
		t.NormalizedValue = normVal.String
		t.Value = val.String
		t.Type = domain.TargetType(tType)
		t.Scope = domain.TargetScope(scopeVal)
		t.Status = domain.TargetStatus(statusVal)
		t.CreatedAt, _ = time.Parse(time.RFC3339, created)
		t.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		if metaJSON.Valid && metaJSON.String != "" {
			_ = json.Unmarshal([]byte(metaJSON.String), &t.Metadata)
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// DeleteTarget removes a target.
func (db *DB) DeleteTarget(id string) error {
	_, err := db.Exec("DELETE FROM targets WHERE id = ?", id)
	return err
}

// -------------------------------------------------------------------
// Scope Rules
// -------------------------------------------------------------------

// InsertScopeRule inserts a new scope rule.
func (db *DB) InsertScopeRule(tx *sql.Tx, r *domain.ScopeRule) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	query := `INSERT INTO scope_rules (id, workspace_id, rule_type, target_type, pattern, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{r.ID, r.WorkspaceID, string(r.RuleType), string(r.TargetType), r.Pattern, r.Description, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListScopeRules returns all scope rules for a workspace.
func (db *DB) ListScopeRules(workspaceID string) ([]*domain.ScopeRule, error) {
	rows, err := db.Query(`SELECT id, workspace_id, rule_type, target_type, pattern, description, created_at
		FROM scope_rules WHERE workspace_id = ? ORDER BY id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*domain.ScopeRule
	for rows.Next() {
		r := &domain.ScopeRule{}
		var ruleType, targetType, desc, created string
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &ruleType, &targetType, &r.Pattern, &desc, &created); err != nil {
			return nil, err
		}
		r.RuleType = domain.ScopeRuleType(ruleType)
		r.TargetType = domain.TargetType(targetType)
		r.Description = desc
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteScopeRule removes a scope rule by ID.
func (db *DB) DeleteScopeRule(id string) error {
	_, err := db.Exec("DELETE FROM scope_rules WHERE id = ?", id)
	return err
}

// -------------------------------------------------------------------
// Tags
// -------------------------------------------------------------------

// InsertTag adds a tag to an entity.
func (db *DB) InsertTag(tx *sql.Tx, t *domain.Tag) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT OR IGNORE INTO tags (id, entity_type, entity_id, name, created_at) VALUES (?, ?, ?, ?, ?)`
	args := []interface{}{t.ID, t.EntityType, t.EntityID, t.Name, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// DeleteTag removes a tag by entity and name.
func (db *DB) DeleteTag(entityType, entityID, name string) error {
	_, err := db.Exec("DELETE FROM tags WHERE entity_type = ? AND entity_id = ? AND name = ?", entityType, entityID, name)
	return err
}

// ListTagsByEntity returns all tags for an entity.
func (db *DB) ListTagsByEntity(entityType, entityID string) ([]*domain.Tag, error) {
	rows, err := db.Query(`SELECT id, entity_type, entity_id, name, created_at FROM tags WHERE entity_type = ? AND entity_id = ? ORDER BY name`, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []*domain.Tag
	for rows.Next() {
		t := &domain.Tag{}
		var created string
		if err := rows.Scan(&t.ID, &t.EntityType, &t.EntityID, &t.Name, &created); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339, created)
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

// ListAssetsByTag returns assets with a specific tag.
func (db *DB) ListAssetsByTag(workspaceID, tagName string) ([]*domain.Asset, error) {
	rows, err := db.Query(`SELECT a.id, a.workspace_id, a.hostname, a.first_observed, a.last_observed, a.created_at, a.updated_at
		FROM assets a JOIN tags t ON t.entity_type = 'asset' AND t.entity_id = a.id
		WHERE a.workspace_id = ? AND t.name = ? ORDER BY a.id`, workspaceID, tagName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*domain.Asset
	for rows.Next() {
		a := &domain.Asset{}
		var firstObs, lastObs, created, updated string
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.Hostname, &firstObs, &lastObs, &created, &updated); err != nil {
			return nil, err
		}
		a.FirstObserved, _ = time.Parse(time.RFC3339, firstObs)
		a.LastObserved, _ = time.Parse(time.RFC3339, lastObs)
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		a.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// -------------------------------------------------------------------
// Notes
// -------------------------------------------------------------------

// InsertNote adds a note to an entity.
func (db *DB) InsertNote(tx *sql.Tx, n *domain.Note) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO notes (id, entity_type, entity_id, content, created_at) VALUES (?, ?, ?, ?, ?)`
	args := []interface{}{n.ID, n.EntityType, n.EntityID, n.Content, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListNotesByEntity returns all notes for an entity.
func (db *DB) ListNotesByEntity(entityType, entityID string) ([]*domain.Note, error) {
	rows, err := db.Query(`SELECT id, entity_type, entity_id, content, created_at FROM notes WHERE entity_type = ? AND entity_id = ? ORDER BY created_at`, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []*domain.Note
	for rows.Next() {
		n := &domain.Note{}
		var created string
		if err := rows.Scan(&n.ID, &n.EntityType, &n.EntityID, &n.Content, &created); err != nil {
			return nil, err
		}
		n.CreatedAt, _ = time.Parse(time.RFC3339, created)
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

// -------------------------------------------------------------------
// Audit Events
// -------------------------------------------------------------------

// InsertAuditEvent records an audit event.
func (db *DB) InsertAuditEvent(tx *sql.Tx, e *domain.AuditEvent) error {
	now := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO audit_events (id, workspace_id, action, entity_type, entity_id, detail, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{e.ID, e.WorkspaceID, string(e.Action), e.EntityType, e.EntityID, e.Detail, now}
	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// ListAuditEvents returns audit events for a workspace.
func (db *DB) ListAuditEvents(workspaceID string) ([]*domain.AuditEvent, error) {
	rows, err := db.Query(`SELECT id, workspace_id, action, entity_type, entity_id, detail, created_at
		FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*domain.AuditEvent
	for rows.Next() {
		e := &domain.AuditEvent{}
		var action, created string
		var entType, entID, detail sql.NullString
		if err := rows.Scan(&e.ID, &e.WorkspaceID, &action, &entType, &entID, &detail, &created); err != nil {
			return nil, err
		}
		e.Action = domain.AuditAction(action)
		e.EntityType = entType.String
		e.EntityID = entID.String
		e.Detail = detail.String
		e.CreatedAt, _ = time.Parse(time.RFC3339, created)
		events = append(events, e)
	}
	return events, rows.Err()
}

// -------------------------------------------------------------------
// Saved Queries
// -------------------------------------------------------------------

// InsertSavedQuery inserts a saved query.
func (db *DB) InsertSavedQuery(q *domain.SavedQuery) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`INSERT OR REPLACE INTO saved_queries (id, workspace_id, name, command, created_at) VALUES (?, ?, ?, ?, ?)`,
		q.ID, q.WorkspaceID, q.Name, q.Command, now)
	return err
}

// GetSavedQuery retrieves a saved query by name.
func (db *DB) GetSavedQuery(workspaceID, name string) (*domain.SavedQuery, error) {
	q := &domain.SavedQuery{}
	var created string
	err := db.QueryRow(`SELECT id, workspace_id, name, command, created_at FROM saved_queries WHERE workspace_id = ? AND name = ?`,
		workspaceID, name).Scan(&q.ID, &q.WorkspaceID, &q.Name, &q.Command, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	q.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return q, nil
}

// ListSavedQueries returns all saved queries for a workspace.
func (db *DB) ListSavedQueries(workspaceID string) ([]*domain.SavedQuery, error) {
	rows, err := db.Query(`SELECT id, workspace_id, name, command, created_at FROM saved_queries WHERE workspace_id = ? ORDER BY name`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var queries []*domain.SavedQuery
	for rows.Next() {
		q := &domain.SavedQuery{}
		var created string
		if err := rows.Scan(&q.ID, &q.WorkspaceID, &q.Name, &q.Command, &created); err != nil {
			return nil, err
		}
		q.CreatedAt, _ = time.Parse(time.RFC3339, created)
		queries = append(queries, q)
	}
	return queries, rows.Err()
}

// DeleteSavedQuery removes a saved query.
func (db *DB) DeleteSavedQuery(workspaceID, name string) error {
	_, err := db.Exec("DELETE FROM saved_queries WHERE workspace_id = ? AND name = ?", workspaceID, name)
	return err
}

// -------------------------------------------------------------------
// Last Import / Assessment timestamps
// -------------------------------------------------------------------

// LastImportTime returns the most recent import audit event timestamp.
func (db *DB) LastImportTime(workspaceID string) (string, error) {
	var ts sql.NullString
	err := db.QueryRow(`SELECT created_at FROM audit_events WHERE workspace_id = ? AND action = 'import' ORDER BY created_at DESC LIMIT 1`,
		workspaceID).Scan(&ts)
	if err == sql.ErrNoRows || !ts.Valid {
		return "", nil
	}
	return ts.String, err
}

// LastAssessmentTime returns the most recent assessment timestamp.
func (db *DB) LastAssessmentTime(workspaceID string) (string, error) {
	var ts sql.NullString
	err := db.QueryRow(`SELECT created_at FROM assessments WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 1`,
		workspaceID).Scan(&ts)
	if err == sql.ErrNoRows || !ts.Valid {
		return "", nil
	}
	return ts.String, err
}

// -------------------------------------------------------------------
// Global Search
// -------------------------------------------------------------------

// SearchResult represents a search match across entity types.
type SearchResult struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Field      string `json:"field"`
	Value      string `json:"value"`
}

// Search performs a global search across all entity types.
func (db *DB) Search(workspaceID, query string) ([]SearchResult, error) {
	q := "%" + query + "%"
	var results []SearchResult

	// Search assets
	rows, err := db.Query(`SELECT id, hostname FROM assets WHERE workspace_id = ? AND (id LIKE ? OR hostname LIKE ?)`,
		workspaceID, q, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, hostname string
		rows.Scan(&id, &hostname)
		field := "id"
		val := id
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(query)) {
			field = "hostname"
			val = hostname
		}
		results = append(results, SearchResult{EntityType: "asset", EntityID: id, Field: field, Value: val})
	}
	rows.Close()

	// Search services
	rows, err = db.Query(`SELECT s.id, s.service_name, s.technology FROM services s JOIN assets a ON s.asset_id = a.id
		WHERE a.workspace_id = ? AND (s.service_name LIKE ? OR s.technology LIKE ? OR CAST(s.port AS TEXT) LIKE ?)`,
		workspaceID, q, q, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var svcName, tech sql.NullString
		rows.Scan(&id, &svcName, &tech)
		val := svcName.String
		field := "service_name"
		if strings.Contains(strings.ToLower(tech.String), strings.ToLower(query)) {
			val = tech.String
			field = "technology"
		}
		results = append(results, SearchResult{EntityType: "service", EntityID: id, Field: field, Value: val})
	}
	rows.Close()

	// Search evidence
	rows, err = db.Query(`SELECT id, description, technology FROM evidence WHERE workspace_id = ?
		AND (description LIKE ? OR technology LIKE ? OR address LIKE ?)`, workspaceID, q, q, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var desc, tech sql.NullString
		rows.Scan(&id, &desc, &tech)
		val := desc.String
		if val == "" {
			val = tech.String
		}
		results = append(results, SearchResult{EntityType: "evidence", EntityID: id, Field: "description", Value: val})
	}
	rows.Close()

	// Search findings
	rows, err = db.Query(`SELECT id, title FROM findings WHERE workspace_id = ? AND (title LIKE ? OR description LIKE ?)`,
		workspaceID, q, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, title string
		rows.Scan(&id, &title)
		results = append(results, SearchResult{EntityType: "finding", EntityID: id, Field: "title", Value: title})
	}
	rows.Close()

	// Search tags
	rows, err = db.Query(`SELECT entity_type, entity_id, name FROM tags WHERE name LIKE ?`, q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var entType, entID, name string
		rows.Scan(&entType, &entID, &name)
		results = append(results, SearchResult{EntityType: "tag:" + entType, EntityID: entID, Field: "tag", Value: name})
	}
	rows.Close()

	return results, nil
}

// -------------------------------------------------------------------
// Source Statistics
// -------------------------------------------------------------------

// SourceStats returns observation/evidence counts per source.
type SourceStats struct {
	SourceID     string
	Observations int
	Evidence     int
}

// GetSourceStats returns statistics for each source in a workspace.
func (db *DB) GetSourceStats(workspaceID string) ([]SourceStats, error) {
	rows, err := db.Query(`SELECT source_id, COUNT(*) as cnt FROM evidence WHERE workspace_id = ? GROUP BY source_id ORDER BY source_id`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []SourceStats
	for rows.Next() {
		var s SourceStats
		if err := rows.Scan(&s.SourceID, &s.Evidence); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

// -------------------------------------------------------------------
// Export support
// -------------------------------------------------------------------

// ExportData contains all workspace data for portable export.
type ExportData struct {
	Version       string              `json:"version"`
	SchemaVersion int                 `json:"schema_version"`
	ExportedAt    string              `json:"exported_at"`
	Workspace     string              `json:"workspace"`
	Assets        []*domain.Asset     `json:"assets"`
	Interfaces    []*domain.Interface `json:"interfaces"`
	Services      []*domain.Service   `json:"services"`
	Networks      []*domain.Network   `json:"networks"`
	Evidence      []*domain.Evidence  `json:"evidence"`
	Findings      []*domain.Finding   `json:"findings"`
	Targets       []*domain.Target    `json:"targets"`
}

// ExportWorkspace exports all data for a workspace.
func (db *DB) ExportWorkspace(workspaceID string) (*ExportData, error) {
	assets, err := db.ListAssets(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting assets: %w", err)
	}
	ifaces, err := db.ListInterfaces(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting interfaces: %w", err)
	}
	services, err := db.ListServices(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting services: %w", err)
	}
	networks, err := db.ListNetworks(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting networks: %w", err)
	}
	evidence, err := db.ListEvidence(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting evidence: %w", err)
	}
	findings, err := db.ListFindings(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting findings: %w", err)
	}
	targets, err := db.ListTargets(workspaceID)
	if err != nil {
		return nil, fmt.Errorf("exporting targets: %w", err)
	}

	schemaVer, _ := db.SchemaVersion()

	return &ExportData{
		Version:       "4.0.0",
		SchemaVersion: schemaVer,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Workspace:     workspaceID,
		Assets:        assets,
		Interfaces:    ifaces,
		Services:      services,
		Networks:      networks,
		Evidence:      evidence,
		Findings:      findings,
		Targets:       targets,
	}, nil
}

// -------------------------------------------------------------------
// Assessment Runs
// -------------------------------------------------------------------

// InsertAssessmentRun records a new assessment execution run.
func (db *DB) InsertAssessmentRun(tx *sql.Tx, r *domain.AssessmentRun) error {
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = now
	}

	var planJSON sql.NullString
	if r.Plan != nil {
		b, _ := json.Marshal(r.Plan)
		planJSON = sql.NullString{String: string(b), Valid: true}
	}

	var statsJSON sql.NullString
	if len(r.CollectorStats) > 0 {
		b, _ := json.Marshal(r.CollectorStats)
		statsJSON = sql.NullString{String: string(b), Valid: true}
	}

	var errorsJSON sql.NullString
	if len(r.Errors) > 0 {
		b, _ := json.Marshal(r.Errors)
		errorsJSON = sql.NullString{String: string(b), Valid: true}
	}

	var completedStr sql.NullString
	if !r.CompletedAt.IsZero() {
		completedStr = sql.NullString{String: r.CompletedAt.Format(time.RFC3339), Valid: true}
	}

	query := `INSERT INTO assessment_runs (id, workspace_id, target_id, target_value, plan_json, status, started_at, completed_at, collector_stats, errors, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []interface{}{
		r.ID,
		r.WorkspaceID,
		r.TargetID,
		r.TargetValue,
		planJSON,
		string(r.Status),
		r.StartedAt.Format(time.RFC3339),
		completedStr,
		statsJSON,
		errorsJSON,
		r.CreatedAt.Format(time.RFC3339),
	}

	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// UpdateAssessmentRun updates an assessment run record.
func (db *DB) UpdateAssessmentRun(tx *sql.Tx, r *domain.AssessmentRun) error {
	var statsJSON sql.NullString
	if len(r.CollectorStats) > 0 {
		b, _ := json.Marshal(r.CollectorStats)
		statsJSON = sql.NullString{String: string(b), Valid: true}
	}

	var errorsJSON sql.NullString
	if len(r.Errors) > 0 {
		b, _ := json.Marshal(r.Errors)
		errorsJSON = sql.NullString{String: string(b), Valid: true}
	}

	var completedStr sql.NullString
	if !r.CompletedAt.IsZero() {
		completedStr = sql.NullString{String: r.CompletedAt.Format(time.RFC3339), Valid: true}
	}

	query := `UPDATE assessment_runs SET status = ?, completed_at = ?, collector_stats = ?, errors = ? WHERE id = ?`
	args := []interface{}{
		string(r.Status),
		completedStr,
		statsJSON,
		errorsJSON,
		r.ID,
	}

	if tx != nil {
		_, err := tx.Exec(query, args...)
		return err
	}
	_, err := db.Exec(query, args...)
	return err
}

// GetAssessmentRun retrieves an assessment run by ID.
func (db *DB) GetAssessmentRun(id string) (*domain.AssessmentRun, error) {
	r := &domain.AssessmentRun{}
	var status, started, created string
	var targetID, targetVal, planJSON, completed, statsJSON, errorsJSON sql.NullString

	err := db.QueryRow(`SELECT id, workspace_id, target_id, target_value, plan_json, status, started_at, completed_at, collector_stats, errors, created_at
		FROM assessment_runs WHERE id = ?`, id).
		Scan(&r.ID, &r.WorkspaceID, &targetID, &targetVal, &planJSON, &status, &started, &completed, &statsJSON, &errorsJSON, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	r.TargetID = targetID.String
	r.TargetValue = targetVal.String
	r.Status = domain.RunStatus(status)
	r.StartedAt, _ = time.Parse(time.RFC3339, started)
	r.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if completed.Valid && completed.String != "" {
		r.CompletedAt, _ = time.Parse(time.RFC3339, completed.String)
	}
	if planJSON.Valid && planJSON.String != "" {
		_ = json.Unmarshal([]byte(planJSON.String), &r.Plan)
	}
	if statsJSON.Valid && statsJSON.String != "" {
		_ = json.Unmarshal([]byte(statsJSON.String), &r.CollectorStats)
	}
	if errorsJSON.Valid && errorsJSON.String != "" {
		_ = json.Unmarshal([]byte(errorsJSON.String), &r.Errors)
	}
	return r, nil
}

// GetLatestAssessmentRun retrieves the most recent assessment run for a workspace.
func (db *DB) GetLatestAssessmentRun(workspaceID string) (*domain.AssessmentRun, error) {
	var id string
	err := db.QueryRow(`SELECT id FROM assessment_runs WHERE workspace_id = ? ORDER BY started_at DESC LIMIT 1`, workspaceID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return db.GetAssessmentRun(id)
}

// ListAssessmentRuns retrieves all assessment runs for a workspace.
func (db *DB) ListAssessmentRuns(workspaceID string) ([]*domain.AssessmentRun, error) {
	rows, err := db.Query(`SELECT id, workspace_id, target_id, target_value, plan_json, status, started_at, completed_at, collector_stats, errors, created_at
		FROM assessment_runs WHERE workspace_id = ? ORDER BY started_at DESC`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*domain.AssessmentRun
	for rows.Next() {
		r := &domain.AssessmentRun{}
		var status, started, created string
		var targetID, targetVal, planJSON, completed, statsJSON, errorsJSON sql.NullString
		if err := rows.Scan(&r.ID, &r.WorkspaceID, &targetID, &targetVal, &planJSON, &status, &started, &completed, &statsJSON, &errorsJSON, &created); err != nil {
			return nil, err
		}
		r.TargetID = targetID.String
		r.TargetValue = targetVal.String
		r.Status = domain.RunStatus(status)
		r.StartedAt, _ = time.Parse(time.RFC3339, started)
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if completed.Valid && completed.String != "" {
			r.CompletedAt, _ = time.Parse(time.RFC3339, completed.String)
		}
		if planJSON.Valid && planJSON.String != "" {
			_ = json.Unmarshal([]byte(planJSON.String), &r.Plan)
		}
		if statsJSON.Valid && statsJSON.String != "" {
			_ = json.Unmarshal([]byte(statsJSON.String), &r.CollectorStats)
		}
		if errorsJSON.Valid && errorsJSON.String != "" {
			_ = json.Unmarshal([]byte(errorsJSON.String), &r.Errors)
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}
