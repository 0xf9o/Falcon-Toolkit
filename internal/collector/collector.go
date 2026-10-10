package collector

import (
	"context"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
)

// CollectorOptions defines operational parameters for active collection.
type CollectorOptions struct {
	Timeout        time.Duration
	RateLimit      string
	Workers        int
	Ports          []int
	FollowRedirect bool
	UserAgent      string
}

// DefaultOptions returns conservative, safe default collection options.
func DefaultOptions() CollectorOptions {
	return CollectorOptions{
		Timeout:        2 * time.Second,
		RateLimit:      "conservative",
		Workers:        16,
		Ports:          DefaultPorts(),
		FollowRedirect: true,
		UserAgent:      "Falcon-ToolKit/4.0.0 (Authorized Network Assessment)",
	}
}

// DefaultPorts returns standard non-destructive assessment ports.
func DefaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 102, 110, 135, 139, 143, 443, 445,
		502, 993, 995, 1433, 1521, 3306, 3389, 4840, 5432, 5900, 6379,
		8080, 8443, 20000, 44818,
	}
}

// ResultObservation wraps a canonical observation emitted by a collector.
type ResultObservation struct {
	Collector     string
	SourceID      string
	Target        domain.Target
	Timestamp     time.Time
	Confidence    domain.ConfidenceLevel
	Kind          string // "dns", "host", "service", "http", "tls", "protocol"
	Host          *observation.HostObservation
	Network       *observation.NetworkObservation
	Relationships []domain.Relationship
	Metadata      map[string]string
	RawData       string
}

// Collector defines the contract for modular active and passive collectors.
type Collector interface {
	Name() string
	Description() string
	Supports(target domain.Target) bool
	Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error)
}

// Registry manages registered collector implementations.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
	order      []string
}

// NewRegistry creates a new empty collector registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]Collector),
	}
}

// NewDefaultRegistry creates a registry pre-loaded with all standard active collectors.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewDNSCollector())
	r.Register(NewHostCollector())
	r.Register(NewTCPCollector())
	r.Register(NewHTTPCollector())
	r.Register(NewTLSCollector())
	return r
}

// Register registers a new collector.
func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors[c.Name()] = c
	r.order = append(r.order, c.Name())
}

// Get returns a collector by name.
func (r *Registry) Get(name string) (Collector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[name]
	return c, ok
}

// All returns all registered collectors in registration order.
func (r *Registry) All() []Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []Collector
	for _, name := range r.order {
		if c, ok := r.collectors[name]; ok {
			list = append(list, c)
		}
	}
	return list
}

// Applicable returns collectors that support the given target.
func (r *Registry) Applicable(target domain.Target) []Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []Collector
	for _, name := range r.order {
		if c, ok := r.collectors[name]; ok {
			if c.Supports(target) {
				list = append(list, c)
			}
		}
	}
	return list
}
