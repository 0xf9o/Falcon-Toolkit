package active

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/schema"
	"golang.org/x/time/rate"
)

// MatrixProbeSpec defines a probe request for a specific source-destination-port triplet.
type MatrixProbeSpec struct {
	TargetHost string
	Port       int
	Protocol   string
}

// ReachabilityMatrixEngine orchestrates multi-vantage stateful reachability evaluation.
type ReachabilityMatrixEngine struct {
	Timeout   time.Duration
	RateLimit int
	Workers   int
}

// NewReachabilityMatrixEngine creates a stateful reachability evaluation engine.
func NewReachabilityMatrixEngine(timeout time.Duration, rateLimit, workers int) *ReachabilityMatrixEngine {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if rateLimit <= 0 {
		rateLimit = 100
	}
	if workers <= 0 {
		workers = 30
	}
	return &ReachabilityMatrixEngine{
		Timeout:   timeout,
		RateLimit: rateLimit,
		Workers:   workers,
	}
}

// EvaluateMatrix performs concurrent reachability probes and returns a mapped matrix.
func (rme *ReachabilityMatrixEngine) EvaluateMatrix(ctx context.Context, hosts []string, ports []int) []schema.ServiceProbeResult {
	limiter := rate.NewLimiter(rate.Limit(rme.RateLimit), 10)
	var specs []MatrixProbeSpec

	for _, h := range hosts {
		for _, p := range ports {
			specs = append(specs, MatrixProbeSpec{
				TargetHost: h,
				Port:       p,
				Protocol:   "tcp",
			})
		}
	}

	jobs := make(chan MatrixProbeSpec, len(specs))
	results := make(chan schema.ServiceProbeResult, len(specs))

	var wg sync.WaitGroup
	workers := rme.Workers
	if workers > len(specs) {
		workers = len(specs)
	}
	if workers < 1 {
		workers = 1
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					_ = limiter.Wait(ctx)
					res := rme.probeStateful(ctx, spec)
					results <- res
				}
			}
		}()
	}

	for _, s := range specs {
		jobs <- s
	}
	close(jobs)

	wg.Wait()
	close(results)

	var list []schema.ServiceProbeResult
	for r := range results {
		list = append(list, r)
	}
	return list
}

func (rme *ReachabilityMatrixEngine) probeStateful(ctx context.Context, spec MatrixProbeSpec) schema.ServiceProbeResult {
	start := time.Now()
	addr := net.JoinHostPort(spec.TargetHost, fmt.Sprintf("%d", spec.Port))

	res := schema.ServiceProbeResult{
		Protocol:    spec.Protocol,
		Port:        spec.Port,
		ServiceName: defaultServiceName(spec.Port),
		State:       schema.StateFiltered,
		LatencyMs:   0,
	}

	dialer := &net.Dialer{Timeout: rme.Timeout}
	conn, err := dialer.DialContext(ctx, spec.Protocol, addr)
	elapsed := time.Since(start).Milliseconds()
	res.LatencyMs = elapsed

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			res.State = schema.StateTimeout
			res.Banner = "No response before timeout (Firewall Drop or Route Hole)"
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
			res.State = schema.StateRefused
			res.Banner = "Host reached; connection refused (Port Closed or Reject Policy)"
		} else if strings.Contains(err.Error(), "no route") || strings.Contains(err.Error(), "unreachable") {
			res.State = schema.StateIsolated
			res.Banner = "Network unreachable (Strict Isolation / No Routing)"
		} else {
			res.State = schema.StateFiltered
			res.Banner = err.Error()
		}
		return res
	}
	defer conn.Close()

	res.State = schema.StateOpen
	res.Banner = "Reachable: TCP 3-Way Handshake Established"
	return res
}
