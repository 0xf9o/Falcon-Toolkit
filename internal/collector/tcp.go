package collector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/protocol"
)

// TCPCollector performs safe, bounded-concurrency TCP service discovery.
type TCPCollector struct{}

// NewTCPCollector creates a new TCP collector.
func NewTCPCollector() *TCPCollector {
	return &TCPCollector{}
}

func (c *TCPCollector) Name() string {
	return "tcp"
}

func (c *TCPCollector) Description() string {
	return "Discovers open TCP services and service banners with bounded concurrency"
}

func (c *TCPCollector) Supports(target domain.Target) bool {
	switch target.Type {
	case domain.TargetIPv4, domain.TargetIPv6, domain.TargetDomain, domain.TargetHostname, domain.TargetURL:
		return true
	default:
		return false
	}
}

// knownServiceName returns a standard service hint for a port.
func knownServiceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 102:
		return "iso-tsap"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 502:
		return "modbus"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "ms-sql-s"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 4840:
		return "opc-ua"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 20000:
		return "dnp3"
	case 44818:
		return "ethernet-ip"
	default:
		return fmt.Sprintf("tcp-%d", port)
	}
}

func (c *TCPCollector) Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error) {
	now := time.Now().UTC()
	var observations []ResultObservation

	host := target.NormalizedValue
	if target.Type == domain.TargetURL {
		trimmed := strings.TrimPrefix(host, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		host = strings.Split(parts[0], ":")[0]
	}

	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 16
	}
	if workers > len(ports) {
		workers = len(ports)
	}

	type portResult struct {
		port    int
		open    bool
		latency time.Duration
		banner  string
	}

	resultsChan := make(chan portResult, len(ports))
	portsChan := make(chan int, len(ports))

	for _, p := range ports {
		portsChan <- p
	}
	close(portsChan)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portsChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
				d := net.Dialer{Timeout: timeout}
				start := time.Now()
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err == nil {
					latency := time.Since(start)
					var banner string
					_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					buf := make([]byte, 512)
					n, _ := conn.Read(buf)
					if n > 0 {
						banner = strings.TrimSpace(string(buf[:n]))
						banner = strings.Map(func(r rune) rune {
							if r >= 32 && r < 127 {
								return r
							}
							return -1
						}, banner)
					}
					conn.Close()

					resultsChan <- portResult{
						port:    p,
						open:    true,
						latency: latency,
						banner:  banner,
					}
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	identifier := protocol.NewIdentifier()
	var openServices []observation.ServiceObservation
	for res := range resultsChan {
		if !res.open {
			continue
		}

		idRes := identifier.Identify(protocol.ProbeContext{
			Port:   res.port,
			Banner: res.banner,
		})

		svcName := knownServiceName(res.port)
		if idRes.Protocol != "" && !strings.HasPrefix(idRes.Protocol, "tcp-") {
			svcName = strings.ToLower(idRes.Protocol)
		}

		svcObs := observation.ServiceObservation{
			Protocol:    "tcp",
			Port:        res.port,
			State:       domain.ServiceStateOpen,
			ServiceName: svcName,
			Technology:  idRes.Technology,
			Version:     idRes.Version,
			Description: res.banner,
		}
		if svcObs.Description == "" {
			svcObs.Description = idRes.Evidence
		}
		openServices = append(openServices, svcObs)
	}

	if len(openServices) > 0 {
		obs := ResultObservation{
			Collector:  c.Name(),
			SourceID:   fmt.Sprintf("tcp-scan-%s", host),
			Target:     target,
			Timestamp:  now,
			Confidence: domain.ConfidenceObserved,
			Kind:       "service",
			Host: &observation.HostObservation{
				IPAddress:  host,
				ObservedAt: now,
				SourceID:   c.Name(),
				Services:   openServices,
				Tags:       []string{"tcp-discovered"},
			},
			Metadata: map[string]string{
				"open_ports_count": fmt.Sprintf("%d", len(openServices)),
			},
			RawData: fmt.Sprintf("TCP discovery on %s: %d open services", host, len(openServices)),
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
