package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// Repository provides the data access layer on top of a SQLite DB connection.
type Repository struct {
	db *DB
}

// NewRepository creates a new Repository wrapping the given database connection.
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// DB returns the underlying DB connection.
func (r *Repository) DB() *DB {
	return r.db
}

// NextSequence generates the next sequence number for a named sequence.
func (r *Repository) NextSequence(workspace, name string) (int, error) {
	seqName := fmt.Sprintf("%s:%s", workspace, name)
	return r.db.NextSequence(nil, seqName)
}

// -------------------------------------------------------------------
// Workspace
// -------------------------------------------------------------------

func (r *Repository) GetWorkspaceByName(name string) (*domain.Workspace, error) {
	// Workspaces are implicitly represented by their DB file, but we also check/track metadata
	return &domain.Workspace{
		ID:        "WS-" + name,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func (r *Repository) CreateWorkspace(ws *domain.Workspace) error {
	return nil
}

// -------------------------------------------------------------------
// Assets
// -------------------------------------------------------------------

func (r *Repository) SaveAsset(a *domain.Asset) error {
	existing, err := r.db.GetAsset(a.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		_, err := r.db.Exec(`UPDATE assets SET hostname = ?, last_observed = ?, updated_at = ? WHERE id = ?`,
			a.Hostname, a.LastObserved.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), a.ID)
		return err
	}
	return r.db.InsertAsset(nil, a)
}

func (r *Repository) GetAsset(id string) (*domain.Asset, error) {
	return r.db.GetAsset(id)
}

func (r *Repository) GetAssetByHostname(workspace, hostname string) (*domain.Asset, error) {
	a := &domain.Asset{}
	var firstObs, lastObs, created, updated string
	err := r.db.QueryRow(`SELECT id, workspace_id, hostname, first_observed, last_observed, created_at, updated_at
		FROM assets WHERE workspace_id = ? AND LOWER(hostname) = LOWER(?) LIMIT 1`, workspace, hostname).
		Scan(&a.ID, &a.WorkspaceID, &a.Hostname, &firstObs, &lastObs, &created, &updated)
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

func (r *Repository) ListAssets(workspace string) ([]domain.Asset, error) {
	assets, err := r.db.ListAssets(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Asset
	for _, a := range assets {
		if a != nil {
			res = append(res, *a)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Interfaces
// -------------------------------------------------------------------

func (r *Repository) SaveInterface(ifc *domain.Interface) error {
	existing, err := r.GetInterface(ifc.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		_, err := r.db.Exec(`UPDATE interfaces SET address = ?, mac_address = ?, network_id = ?, updated_at = ? WHERE id = ?`,
			ifc.Address, ifc.MACAddress, ifc.NetworkID, time.Now().UTC().Format(time.RFC3339), ifc.ID)
		return err
	}
	return r.db.InsertInterface(nil, ifc)
}

func (r *Repository) GetInterface(id string) (*domain.Interface, error) {
	ifc := &domain.Interface{}
	var created, updated string
	var mac, netID sql.NullString
	err := r.db.QueryRow(`SELECT id, asset_id, address, mac_address, network_id, created_at, updated_at
		FROM interfaces WHERE id = ?`, id).
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

func (r *Repository) GetInterfaceByAddress(workspace, addr string) (*domain.Interface, error) {
	return r.db.FindInterfaceByAddress(workspace, addr)
}

func (r *Repository) ListInterfaces(workspace string) ([]domain.Interface, error) {
	ifaces, err := r.db.ListInterfaces(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Interface
	for _, i := range ifaces {
		if i != nil {
			res = append(res, *i)
		}
	}
	return res, nil
}

func (r *Repository) ListInterfacesByAsset(assetID string) ([]domain.Interface, error) {
	ifaces, err := r.db.ListInterfacesByAsset(assetID)
	if err != nil {
		return nil, err
	}
	var res []domain.Interface
	for _, i := range ifaces {
		if i != nil {
			res = append(res, *i)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Services
// -------------------------------------------------------------------

func (r *Repository) SaveService(s *domain.Service) error {
	existing, err := r.GetService(s.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		_, err := r.db.Exec(`UPDATE services SET state = ?, service_name = ?, technology = ?, version = ?, last_observed = ?, updated_at = ? WHERE id = ?`,
			string(s.State), s.ServiceName, s.Technology, s.Version, s.LastObserved.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), s.ID)
		return err
	}
	return r.db.InsertService(nil, s)
}

func (r *Repository) GetService(id string) (*domain.Service, error) {
	s := &domain.Service{}
	var state, firstObs, lastObs, created, updated string
	var svcName, tech, ver sql.NullString
	err := r.db.QueryRow(`SELECT id, asset_id, protocol, port, state, service_name, technology, version,
		first_observed, last_observed, created_at, updated_at
		FROM services WHERE id = ?`, id).
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

func (r *Repository) GetServiceByAssetProtoPort(assetID, proto string, port int) (*domain.Service, error) {
	return r.db.FindService(assetID, proto, port)
}

func (r *Repository) ListServices(workspace string) ([]domain.Service, error) {
	services, err := r.db.ListServices(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Service
	for _, s := range services {
		if s != nil {
			res = append(res, *s)
		}
	}
	return res, nil
}

func (r *Repository) ListServicesByAsset(assetID string) ([]domain.Service, error) {
	services, err := r.db.ListServicesByAsset(assetID)
	if err != nil {
		return nil, err
	}
	var res []domain.Service
	for _, s := range services {
		if s != nil {
			res = append(res, *s)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Networks
// -------------------------------------------------------------------

func (r *Repository) SaveNetwork(n *domain.Network) error {
	existing, err := r.GetNetwork(n.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		_, err := r.db.Exec(`UPDATE networks SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
			n.Name, n.Description, time.Now().UTC().Format(time.RFC3339), n.ID)
		return err
	}
	return r.db.InsertNetwork(nil, n)
}

func (r *Repository) GetNetwork(id string) (*domain.Network, error) {
	return r.db.GetNetwork(id)
}

func (r *Repository) GetNetworkByCIDR(workspace, cidr string) (*domain.Network, error) {
	return r.db.FindNetworkByCIDR(workspace, cidr)
}

func (r *Repository) ListNetworks(workspace string) ([]domain.Network, error) {
	networks, err := r.db.ListNetworks(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Network
	for _, n := range networks {
		if n != nil {
			res = append(res, *n)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Relationships
// -------------------------------------------------------------------

func (r *Repository) SaveRelationship(rel *domain.Relationship) error {
	return r.db.InsertRelationship(nil, rel)
}

func (r *Repository) ListRelationships(workspace string) ([]domain.Relationship, error) {
	rels, err := r.db.ListRelationships(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Relationship
	for _, rel := range rels {
		if rel != nil {
			res = append(res, *rel)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Evidence
// -------------------------------------------------------------------

func (r *Repository) SaveEvidence(e *domain.Evidence) error {
	return r.db.InsertEvidence(nil, e)
}

func (r *Repository) GetEvidence(id string) (*domain.Evidence, error) {
	return r.db.GetEvidence(id)
}

func (r *Repository) ListEvidence(workspace string) ([]domain.Evidence, error) {
	evidenceList, err := r.db.ListEvidence(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Evidence
	for _, e := range evidenceList {
		if e != nil {
			res = append(res, *e)
		}
	}
	return res, nil
}

func (r *Repository) ListEvidenceByEntity(entityType, entityID string) ([]domain.Evidence, error) {
	evidenceList, err := r.db.ListEvidenceByEntity(entityID)
	if err != nil {
		return nil, err
	}
	var res []domain.Evidence
	for _, e := range evidenceList {
		if e != nil && (entityType == "" || strings.EqualFold(e.EntityType, entityType)) {
			res = append(res, *e)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Findings
// -------------------------------------------------------------------

func (r *Repository) SaveFinding(f *domain.Finding) error {
	existing, err := r.GetFinding(f.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := r.db.Exec(`UPDATE findings SET status = ?, description = ?, title = ?, last_observed = ?, updated_at = ? WHERE id = ?`,
			string(f.Status), f.Description, f.Title, f.LastObserved.Format(time.RFC3339), now, f.ID)
		return err
	}
	return r.db.InsertFinding(nil, f)
}

func (r *Repository) GetFinding(id string) (*domain.Finding, error) {
	return r.db.GetFinding(id)
}

func (r *Repository) ListFindings(workspace string) ([]domain.Finding, error) {
	findings, err := r.db.ListFindings(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Finding
	for _, f := range findings {
		if f != nil {
			res = append(res, *f)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Assessments & Snapshots
// -------------------------------------------------------------------

func (r *Repository) SaveAssessment(a *domain.Assessment) error {
	return r.db.InsertAssessment(nil, a)
}

func (r *Repository) SaveAssessmentSnapshot(s *domain.AssessmentSnapshot) error {
	// Ensure parent assessment record exists to satisfy foreign key constraints
	if s.AssessmentID != "" {
		_ = r.db.InsertAssessment(nil, &domain.Assessment{
			ID:             s.AssessmentID,
			WorkspaceID:    s.WorkspaceID,
			RulesetVersion: "4.0",
			SchemaVersion:  "4.0",
			CreatedAt:      s.CreatedAt,
		})
	}
	return r.db.InsertAssessmentSnapshot(nil, s)
}

func (r *Repository) GetAssessmentSnapshotByAssessmentID(assessID string) (*domain.AssessmentSnapshot, error) {
	s := &domain.AssessmentSnapshot{}
	var created string
	err := r.db.QueryRow(`SELECT id, assessment_id, workspace_id, snapshot_data, created_at
		FROM assessment_snapshots WHERE assessment_id = ? OR id = ? LIMIT 1`, assessID, assessID).
		Scan(&s.ID, &s.AssessmentID, &s.WorkspaceID, &s.SnapshotData, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return s, nil
}

// -------------------------------------------------------------------
// Audit Events
// -------------------------------------------------------------------

func (r *Repository) RecordAuditEvent(e *domain.AuditEvent) error {
	return r.db.InsertAuditEvent(nil, e)
}

func (r *Repository) ListAuditEvents(workspace string) ([]domain.AuditEvent, error) {
	events, err := r.db.ListAuditEvents(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.AuditEvent
	for _, e := range events {
		if e != nil {
			res = append(res, *e)
		}
	}
	return res, nil
}

// -------------------------------------------------------------------
// Tags & Notes & Saved Queries
// -------------------------------------------------------------------

func (r *Repository) SaveTag(t *domain.Tag) error {
	return r.db.InsertTag(nil, t)
}

func (r *Repository) ListTagsByEntity(entityType, entityID string) ([]domain.Tag, error) {
	tags, err := r.db.ListTagsByEntity(entityType, entityID)
	if err != nil {
		return nil, err
	}
	var res []domain.Tag
	for _, t := range tags {
		if t != nil {
			res = append(res, *t)
		}
	}
	return res, nil
}

func (r *Repository) SaveNote(n *domain.Note) error {
	return r.db.InsertNote(nil, n)
}

func (r *Repository) ListNotesByEntity(entityType, entityID string) ([]domain.Note, error) {
	notes, err := r.db.ListNotesByEntity(entityType, entityID)
	if err != nil {
		return nil, err
	}
	var res []domain.Note
	for _, n := range notes {
		if n != nil {
			res = append(res, *n)
		}
	}
	return res, nil
}

func (r *Repository) SaveQuery(q *domain.SavedQuery) error {
	return r.db.InsertSavedQuery(q)
}

func (r *Repository) ListSavedQueries(workspace string) ([]domain.SavedQuery, error) {
	queries, err := r.db.ListSavedQueries(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.SavedQuery
	for _, q := range queries {
		if q != nil {
			res = append(res, *q)
		}
	}
	return res, nil
}

func (r *Repository) GetSavedQuery(workspace, name string) (*domain.SavedQuery, error) {
	return r.db.GetSavedQuery(workspace, name)
}

// -------------------------------------------------------------------
// Targets
// -------------------------------------------------------------------

func (r *Repository) SaveTarget(t *domain.Target) error {
	existing, _ := r.db.GetTarget(t.ID)
	if existing != nil {
		return r.db.UpdateTarget(nil, t)
	}
	return r.db.InsertTarget(nil, t)
}

func (r *Repository) GetTarget(id string) (*domain.Target, error) {
	return r.db.GetTarget(id)
}

func (r *Repository) GetTargetByNormalizedValue(workspace, normVal string) (*domain.Target, error) {
	return r.db.GetTargetByNormalizedValue(workspace, normVal)
}

func (r *Repository) ListTargets(workspace string) ([]domain.Target, error) {
	targets, err := r.db.ListTargets(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.Target
	for _, t := range targets {
		if t != nil {
			res = append(res, *t)
		}
	}
	return res, nil
}

func (r *Repository) DeleteTarget(id string) error {
	return r.db.DeleteTarget(id)
}

// -------------------------------------------------------------------
// Scope Rules
// -------------------------------------------------------------------

func (r *Repository) SaveScopeRule(rule *domain.ScopeRule) error {
	return r.db.InsertScopeRule(nil, rule)
}

func (r *Repository) ListScopeRules(workspace string) ([]domain.ScopeRule, error) {
	rules, err := r.db.ListScopeRules(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.ScopeRule
	for _, rule := range rules {
		if rule != nil {
			res = append(res, *rule)
		}
	}
	return res, nil
}

func (r *Repository) DeleteScopeRule(id string) error {
	return r.db.DeleteScopeRule(id)
}

// -------------------------------------------------------------------
// Engagements & Objectives
// -------------------------------------------------------------------

func (r *Repository) SaveEngagement(e *domain.Engagement) error {
	now := time.Now().UTC().Format(time.RFC3339)
	existing, _ := r.GetEngagement(e.ID)
	if existing != nil {
		_, err := r.db.Exec(`UPDATE engagements SET name = ?, type = ?, status = ?, description = ?, updated_at = ? WHERE id = ?`,
			e.Name, e.Type, string(e.Status), e.Description, now, e.ID)
		return err
	}
	_, err := r.db.Exec(`INSERT INTO engagements (id, workspace_id, name, type, status, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.WorkspaceID, e.Name, e.Type, string(e.Status), e.Description, now, now)
	return err
}

func (r *Repository) GetEngagement(id string) (*domain.Engagement, error) {
	e := &domain.Engagement{}
	var status, created, updated string
	var desc sql.NullString
	err := r.db.QueryRow(`SELECT id, workspace_id, name, type, status, description, created_at, updated_at
		FROM engagements WHERE id = ?`, id).
		Scan(&e.ID, &e.WorkspaceID, &e.Name, &e.Type, &status, &desc, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Status = domain.EngagementStatus(status)
	e.Description = desc.String
	e.CreatedAt, _ = time.Parse(time.RFC3339, created)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	e.Objectives, _ = r.ListObjectives(e.ID)
	return e, nil
}

func (r *Repository) GetActiveEngagement(workspace string) (*domain.Engagement, error) {
	e := &domain.Engagement{}
	var status, created, updated string
	var desc sql.NullString
	err := r.db.QueryRow(`SELECT id, workspace_id, name, type, status, description, created_at, updated_at
		FROM engagements WHERE workspace_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`, workspace).
		Scan(&e.ID, &e.WorkspaceID, &e.Name, &e.Type, &status, &desc, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Status = domain.EngagementStatus(status)
	e.Description = desc.String
	e.CreatedAt, _ = time.Parse(time.RFC3339, created)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	e.Objectives, _ = r.ListObjectives(e.ID)
	return e, nil
}

func (r *Repository) ListEngagements(workspace string) ([]domain.Engagement, error) {
	rows, err := r.db.Query(`SELECT id, workspace_id, name, type, status, description, created_at, updated_at
		FROM engagements WHERE workspace_id = ? ORDER BY created_at DESC`, workspace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Engagement
	for rows.Next() {
		e := domain.Engagement{}
		var status, created, updated string
		var desc sql.NullString
		if err := rows.Scan(&e.ID, &e.WorkspaceID, &e.Name, &e.Type, &status, &desc, &created, &updated); err != nil {
			return nil, err
		}
		e.Status = domain.EngagementStatus(status)
		e.Description = desc.String
		e.CreatedAt, _ = time.Parse(time.RFC3339, created)
		e.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		e.Objectives, _ = r.ListObjectives(e.ID)
		list = append(list, e)
	}
	return list, rows.Err()
}

func (r *Repository) SaveObjective(o *domain.Objective) error {
	now := time.Now().UTC().Format(time.RFC3339)
	compl := 0
	if o.Completed {
		compl = 1
	}
	_, err := r.db.Exec(`INSERT OR REPLACE INTO objectives (id, engagement_id, title, completed, created_at)
		VALUES (?, ?, ?, ?, ?)`, o.ID, o.EngagementID, o.Title, compl, now)
	return err
}

func (r *Repository) ListObjectives(engagementID string) ([]domain.Objective, error) {
	rows, err := r.db.Query(`SELECT id, engagement_id, title, completed, created_at FROM objectives WHERE engagement_id = ? ORDER BY created_at`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.Objective
	for rows.Next() {
		o := domain.Objective{}
		var compl int
		var created string
		if err := rows.Scan(&o.ID, &o.EngagementID, &o.Title, &compl, &created); err != nil {
			return nil, err
		}
		o.Completed = compl == 1
		o.CreatedAt, _ = time.Parse(time.RFC3339, created)
		list = append(list, o)
	}
	return list, rows.Err()
}

// -------------------------------------------------------------------
// Snapshots
// -------------------------------------------------------------------

func (r *Repository) ListAssessmentSnapshots(workspace string) ([]domain.AssessmentSnapshot, error) {
	rows, err := r.db.Query(`SELECT id, assessment_id, workspace_id, snapshot_data, created_at FROM assessment_snapshots WHERE workspace_id = ? ORDER BY created_at DESC`, workspace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.AssessmentSnapshot
	for rows.Next() {
		s := domain.AssessmentSnapshot{}
		var created string
		if err := rows.Scan(&s.ID, &s.AssessmentID, &s.WorkspaceID, &s.SnapshotData, &created); err != nil {
			return nil, err
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, created)
		list = append(list, s)
	}
	return list, rows.Err()
}

// -------------------------------------------------------------------
// Search
// -------------------------------------------------------------------

func (r *Repository) Search(workspace, query string) ([]SearchResult, error) {
	return r.db.Search(workspace, query)
}

// -------------------------------------------------------------------
// Timeline
// -------------------------------------------------------------------

func (r *Repository) GetTimeline(workspace string) ([]domain.TimelineItem, error) {
	var items []domain.TimelineItem

	// 1. Audit events
	audits, _ := r.ListAuditEvents(workspace)
	for _, a := range audits {
		items = append(items, domain.TimelineItem{
			Timestamp:   a.CreatedAt,
			Kind:        "AUDIT",
			EntityID:    a.ID,
			Description: a.Detail,
		})
	}

	// 2. Evidence
	evList, _ := r.ListEvidence(workspace)
	for _, e := range evList {
		items = append(items, domain.TimelineItem{
			Timestamp:   e.ObservedAt,
			Kind:        "EVIDENCE",
			EntityID:    e.ID,
			Description: e.Description,
		})
	}

	// 3. Findings
	findings, _ := r.ListFindings(workspace)
	for _, f := range findings {
		items = append(items, domain.TimelineItem{
			Timestamp:   f.CreatedAt,
			Kind:        "FINDING",
			EntityID:    f.ID,
			Description: fmt.Sprintf("[%s] %s", f.RuleID, f.Title),
		})
	}

	return items, nil
}

// -------------------------------------------------------------------
// Assessment Runs
// -------------------------------------------------------------------

func (r *Repository) SaveAssessmentRun(run *domain.AssessmentRun) error {
	existing, _ := r.db.GetAssessmentRun(run.ID)
	if existing != nil {
		return r.db.UpdateAssessmentRun(nil, run)
	}
	return r.db.InsertAssessmentRun(nil, run)
}

func (r *Repository) GetAssessmentRun(id string) (*domain.AssessmentRun, error) {
	return r.db.GetAssessmentRun(id)
}

func (r *Repository) GetLatestAssessmentRun(workspace string) (*domain.AssessmentRun, error) {
	return r.db.GetLatestAssessmentRun(workspace)
}

func (r *Repository) ListAssessmentRuns(workspace string) ([]domain.AssessmentRun, error) {
	runs, err := r.db.ListAssessmentRuns(workspace)
	if err != nil {
		return nil, err
	}
	var res []domain.AssessmentRun
	for _, run := range runs {
		if run != nil {
			res = append(res, *run)
		}
	}
	return res, nil
}

func (r *Repository) SaveObservation(obs *domain.Observation) error {
	return r.db.InsertObservation(nil, obs)
}

func (r *Repository) CountObservations(workspace string) (int, error) {
	return r.db.CountObservations(workspace)
}
