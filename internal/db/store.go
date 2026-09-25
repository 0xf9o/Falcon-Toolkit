package db

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta       = []byte("metadata")
	bucketWorkspaces = []byte("workspaces")
	keyActiveWs      = []byte("active_workspace")
)

// PortRecord represents a discovered open port entry.
type PortRecord struct {
	Target    string `json:"target"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service,omitempty"`
	Banner    string `json:"banner,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Timestamp string `json:"timestamp"`
}

// SubdomainRecord represents a discovered subdomain and its resolved IPs.
type SubdomainRecord struct {
	Domain    string   `json:"domain"`
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Source    string   `json:"source"`
	Timestamp string   `json:"timestamp"`
}

// WorkspaceData holds combined export data for a workspace.
type WorkspaceData struct {
	Workspace  string            `json:"workspace"`
	ExportedAt string            `json:"exported_at"`
	Ports      []PortRecord      `json:"ports"`
	Subdomains []SubdomainRecord `json:"subdomains"`
}

// Store wraps the bbolt embedded database for thread-safe persistent operations.
type Store struct {
	db *bolt.DB
}

// Open initializes or connects to the local bbolt database.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded db: %w", err)
	}

	// Initialize root buckets
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketMeta); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketWorkspaces); err != nil {
			return err
		}

		// Ensure default workspace exists
		meta := tx.Bucket(bucketMeta)
		if meta.Get(keyActiveWs) == nil {
			if err := meta.Put(keyActiveWs, []byte("default")); err != nil {
				return err
			}
		}

		wsBucket := tx.Bucket(bucketWorkspaces)
		if wsBucket.Get([]byte("default")) == nil {
			if err := wsBucket.Put([]byte("default"), []byte(time.Now().Format(time.RFC3339))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close gracefully closes the embedded database.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetActiveWorkspace returns the name of the currently selected workspace.
func (s *Store) GetActiveWorkspace() (string, error) {
	var ws string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		val := b.Get(keyActiveWs)
		if val == nil {
			ws = "default"
		} else {
			ws = string(val)
		}
		return nil
	})
	return ws, err
}

// SetActiveWorkspace sets or creates a workspace as active.
func (s *Store) SetActiveWorkspace(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("workspace name cannot be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if err := meta.Put(keyActiveWs, []byte(name)); err != nil {
			return err
		}

		wsBucket := tx.Bucket(bucketWorkspaces)
		return wsBucket.Put([]byte(name), []byte(time.Now().Format(time.RFC3339)))
	})
}

// ListWorkspaces returns a list of all existing workspaces.
func (s *Store) ListWorkspaces() ([]string, error) {
	var list []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWorkspaces)
		return b.ForEach(func(k, v []byte) error {
			list = append(list, string(k))
			return nil
		})
	})
	return list, err
}

// bucketName returns bucket key for a given workspace and resource type.
func bucketName(workspace, resource string) []byte {
	return []byte(fmt.Sprintf("ws_%s_%s", workspace, resource))
}

// SavePort saves an open port record into the specified workspace.
func (s *Store) SavePort(workspace string, record PortRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().Format(time.RFC3339)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	key := []byte(fmt.Sprintf("%s:%d", record.Target, record.Port))

	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName(workspace, "ports"))
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// GetPorts retrieves all recorded ports for a workspace.
func (s *Store) GetPorts(workspace string) ([]PortRecord, error) {
	var records []PortRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName(workspace, "ports"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var r PortRecord
			if err := json.Unmarshal(v, &r); err == nil {
				records = append(records, r)
			}
			return nil
		})
	})
	return records, err
}

// SaveSubdomain saves a discovered subdomain into the specified workspace.
func (s *Store) SaveSubdomain(workspace string, record SubdomainRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().Format(time.RFC3339)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	key := []byte(record.Subdomain)

	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName(workspace, "subdomains"))
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// GetSubdomains retrieves all recorded subdomains for a workspace.
func (s *Store) GetSubdomains(workspace string) ([]SubdomainRecord, error) {
	var records []SubdomainRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName(workspace, "subdomains"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var r SubdomainRecord
			if err := json.Unmarshal(v, &r); err == nil {
				records = append(records, r)
			}
			return nil
		})
	})
	return records, err
}

// ExportJSON exports all workspace data into a formatted JSON file.
func (s *Store) ExportJSON(workspace, outPath string) error {
	ports, err := s.GetPorts(workspace)
	if err != nil {
		return err
	}
	if ports == nil {
		ports = []PortRecord{}
	}
	subs, err := s.GetSubdomains(workspace)
	if err != nil {
		return err
	}
	if subs == nil {
		subs = []SubdomainRecord{}
	}

	data := WorkspaceData{
		Workspace:  workspace,
		ExportedAt: time.Now().Format(time.RFC3339),
		Ports:      ports,
		Subdomains: subs,
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outPath, bytes, 0644)
}

// ExportCSV exports either ports or subdomains into a CSV file.
func (s *Store) ExportCSV(workspace, category, outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	switch strings.ToLower(category) {
	case "ports", "port":
		ports, err := s.GetPorts(workspace)
		if err != nil {
			return err
		}
		if err := writer.Write([]string{"Target", "Port", "Protocol", "State", "Service", "Banner", "LatencyMs", "Timestamp"}); err != nil {
			return err
		}
		for _, p := range ports {
			row := []string{
				p.Target,
				strconv.Itoa(p.Port),
				p.Protocol,
				p.State,
				p.Service,
				p.Banner,
				strconv.FormatInt(p.LatencyMs, 10),
				p.Timestamp,
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	case "subdomains", "subdomain", "subs":
		subs, err := s.GetSubdomains(workspace)
		if err != nil {
			return err
		}
		if err := writer.Write([]string{"Domain", "Subdomain", "IPs", "Source", "Timestamp"}); err != nil {
			return err
		}
		for _, sub := range subs {
			row := []string{
				sub.Domain,
				sub.Subdomain,
				strings.Join(sub.IPs, "; "),
				sub.Source,
				sub.Timestamp,
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown export category '%s' (use 'ports' or 'subdomains')", category)
	}

	return nil
}
