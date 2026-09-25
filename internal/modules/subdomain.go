package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"falcon/internal/db"
	"falcon/internal/engine"
)

// SubdomainOptions configures passive subdomain discovery.
type SubdomainOptions struct {
	Domain      string
	Workers     int
	TimeoutSec  int
	Workspace   string
	Store       *db.Store
	OnSubFound  func(db.SubdomainRecord)
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// DiscoverSubdomains passively collects subdomains via Certificate Transparency and resolves IPs concurrently.
func DiscoverSubdomains(ctx context.Context, opts SubdomainOptions) ([]db.SubdomainRecord, error) {
	if opts.Workers <= 0 {
		opts.Workers = 25
	}
	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = 15
	}

	opts.Domain = strings.ToLower(strings.TrimSpace(opts.Domain))

	// Step 1: Query Crt.sh Certificate Transparency logs
	rawNames, err := queryCrtSh(ctx, opts.Domain, opts.TimeoutSec)
	if err != nil {
		// Even if crt.sh fails, fallback to root domain resolution
		rawNames = []string{opts.Domain, "www." + opts.Domain, "mail." + opts.Domain, "api." + opts.Domain}
	}

	// Clean and deduplicate candidates
	candidateMap := make(map[string]bool)
	for _, n := range rawNames {
		n = strings.ToLower(strings.TrimSpace(n))
		for _, sub := range strings.Split(n, "\n") {
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "*.")
			if strings.HasSuffix(sub, opts.Domain) && !candidateMap[sub] {
				candidateMap[sub] = true
			}
		}
	}

	var candidates []string
	for sub := range candidateMap {
		candidates = append(candidates, sub)
	}

	// Step 2: Concurrently resolve DNS for discovered subdomains using engine.Pool
	poolCfg := engine.Config{
		Workers:     opts.Workers,
		QueueSize:   len(candidates) + 10,
		TaskTimeout: 2 * time.Second,
	}

	taskFn := func(taskCtx context.Context, sub string) (*db.SubdomainRecord, error) {
		ips, err := resolveSubdomain(taskCtx, sub)
		if err != nil || len(ips) == 0 {
			// Subdomain not actively resolving or NXDOMAIN
			return &db.SubdomainRecord{
				Domain:    opts.Domain,
				Subdomain: sub,
				IPs:       []string{},
				Source:    "crt.sh",
				Timestamp: time.Now().Format(time.RFC3339),
			}, nil
		}

		return &db.SubdomainRecord{
			Domain:    opts.Domain,
			Subdomain: sub,
			IPs:       ips,
			Source:    "crt.sh+dns",
			Timestamp: time.Now().Format(time.RFC3339),
		}, nil
	}

	pool, err := engine.NewPool(ctx, poolCfg, taskFn)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS resolver pool: %w", err)
	}

	go func() {
		for _, c := range candidates {
			select {
			case <-ctx.Done():
				return
			default:
				_ = pool.Submit(ctx, c)
			}
		}
		pool.Stop()
	}()

	var results []db.SubdomainRecord
	for res := range pool.Results() {
		if res.Err != nil || res.Value == nil {
			continue
		}
		rec := *res.Value
		results = append(results, rec)

		if opts.Store != nil && opts.Workspace != "" {
			_ = opts.Store.SaveSubdomain(opts.Workspace, rec)
		}
		if opts.OnSubFound != nil {
			opts.OnSubFound(rec)
		}
	}

	return results, nil
}

// queryCrtSh pulls certificate logs from crt.sh JSON API.
func queryCrtSh(ctx context.Context, domain string, timeoutSec int) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Falcon/3.0 (+https://github.com/falcon)")

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.NameValue)
	}
	return names, nil
}

// resolveSubdomain performs context-aware DNS lookup using net.DefaultResolver.
func resolveSubdomain(ctx context.Context, sub string) ([]string, error) {
	var ips []string
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, sub)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ips = append(ips, addr.IP.String())
	}
	return ips, nil
}
