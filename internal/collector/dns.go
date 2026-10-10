package collector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
)

// DNSCollector performs active DNS resolution for targets.
type DNSCollector struct {
	Resolver *net.Resolver
}

// NewDNSCollector creates a new DNS collector.
func NewDNSCollector() *DNSCollector {
	return &DNSCollector{
		Resolver: net.DefaultResolver,
	}
}

func (c *DNSCollector) Name() string {
	return "dns"
}

func (c *DNSCollector) Description() string {
	return "Resolves domain records (A, AAAA, CNAME, MX, NS, TXT, PTR) with evidence provenance"
}

func (c *DNSCollector) Supports(target domain.Target) bool {
	switch target.Type {
	case domain.TargetDomain, domain.TargetHostname, domain.TargetIPv4, domain.TargetIPv6, domain.TargetURL:
		return true
	default:
		return false
	}
}

func (c *DNSCollector) Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error) {
	var observations []ResultObservation
	now := time.Now().UTC()

	host := target.NormalizedValue
	if target.Type == domain.TargetURL {
		trimmed := strings.TrimPrefix(host, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		host = strings.Split(parts[0], ":")[0]
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout*2)
	defer cancel()

	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// If target is IP, perform reverse PTR lookup
	if target.Type == domain.TargetIPv4 || target.Type == domain.TargetIPv6 {
		names, err := resolver.LookupAddr(resolveCtx, host)
		if err == nil && len(names) > 0 {
			primaryName := strings.TrimSuffix(names[0], ".")
			obs := ResultObservation{
				Collector:  c.Name(),
				SourceID:   fmt.Sprintf("dns-ptr-%s", host),
				Target:     target,
				Timestamp:  now,
				Confidence: domain.ConfidenceObserved,
				Kind:       "dns",
				Host: &observation.HostObservation{
					IPAddress:  host,
					Hostname:   primaryName,
					ObservedAt: now,
					SourceID:   c.Name(),
					Tags:       []string{"dns", "ptr-resolved"},
				},
				Metadata: map[string]string{
					"ptr": strings.Join(names, ", "),
				},
				RawData: fmt.Sprintf("PTR %s -> %s", host, strings.Join(names, ", ")),
			}
			observations = append(observations, obs)
		}
		return observations, nil
	}

	// Target is Domain / Hostname: Query A, AAAA, CNAME, MX, NS, TXT
	meta := make(map[string]string)
	var rawRecords []string

	ips, err := resolver.LookupIPAddr(resolveCtx, host)
	var resolvedIPv4s []string
	var resolvedIPv6s []string
	if err == nil {
		for _, ip := range ips {
			ipStr := ip.IP.String()
			if ip.IP.To4() != nil {
				resolvedIPv4s = append(resolvedIPv4s, ipStr)
				rawRecords = append(rawRecords, fmt.Sprintf("A %s -> %s", host, ipStr))
			} else {
				resolvedIPv6s = append(resolvedIPv6s, ipStr)
				rawRecords = append(rawRecords, fmt.Sprintf("AAAA %s -> %s", host, ipStr))
			}

			observations = append(observations, ResultObservation{
				Collector:  c.Name(),
				SourceID:   fmt.Sprintf("dns-resolve-%s-%s", host, ipStr),
				Target:     target,
				Timestamp:  now,
				Confidence: domain.ConfidenceObserved,
				Kind:       "dns",
				Host: &observation.HostObservation{
					IPAddress:  ipStr,
					Hostname:   host,
					ObservedAt: now,
					SourceID:   c.Name(),
					Tags:       []string{"dns", "resolved"},
				},
				Metadata: map[string]string{
					"record_type": "A/AAAA",
					"domain":      host,
					"ip":          ipStr,
				},
				RawData: fmt.Sprintf("Domain %s resolves to %s", host, ipStr),
			})
		}
	}
	if len(resolvedIPv4s) > 0 {
		meta["a_records"] = strings.Join(resolvedIPv4s, ", ")
	}
	if len(resolvedIPv6s) > 0 {
		meta["aaaa_records"] = strings.Join(resolvedIPv6s, ", ")
	}

	cname, err := resolver.LookupCNAME(resolveCtx, host)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != host {
		meta["cname"] = cname
		rawRecords = append(rawRecords, fmt.Sprintf("CNAME %s -> %s", host, cname))
	}

	mxs, err := resolver.LookupMX(resolveCtx, host)
	if err == nil && len(mxs) > 0 {
		var mxStrs []string
		for _, mx := range mxs {
			mxStrs = append(mxStrs, fmt.Sprintf("%s (prio %d)", mx.Host, mx.Pref))
		}
		meta["mx"] = strings.Join(mxStrs, "; ")
		rawRecords = append(rawRecords, fmt.Sprintf("MX %s", strings.Join(mxStrs, ", ")))
	}

	nss, err := resolver.LookupNS(resolveCtx, host)
	if err == nil && len(nss) > 0 {
		var nsStrs []string
		for _, ns := range nss {
			nsStrs = append(nsStrs, ns.Host)
		}
		meta["ns"] = strings.Join(nsStrs, ", ")
		rawRecords = append(rawRecords, fmt.Sprintf("NS %s", strings.Join(nsStrs, ", ")))
	}

	txts, err := resolver.LookupTXT(resolveCtx, host)
	if err == nil && len(txts) > 0 {
		meta["txt"] = strings.Join(txts, " | ")
		rawRecords = append(rawRecords, fmt.Sprintf("TXT %s", strings.Join(txts, " ")))
	}

	if len(rawRecords) > 0 {
		obs := ResultObservation{
			Collector:  c.Name(),
			SourceID:   fmt.Sprintf("dns-meta-%s", host),
			Target:     target,
			Timestamp:  now,
			Confidence: domain.ConfidenceObserved,
			Kind:       "dns",
			Metadata:   meta,
			RawData:    strings.Join(rawRecords, "\n"),
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
