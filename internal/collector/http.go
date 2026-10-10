package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
	"github.com/falcon-toolkit/falcon/internal/observation"
	"github.com/falcon-toolkit/falcon/internal/protocol"
)

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

// HTTPCollector probes HTTP and HTTPS endpoints for metadata, headers, titles, and technologies.
type HTTPCollector struct{}

// NewHTTPCollector creates a new HTTP collector.
func NewHTTPCollector() *HTTPCollector {
	return &HTTPCollector{}
}

func (c *HTTPCollector) Name() string {
	return "http"
}

func (c *HTTPCollector) Description() string {
	return "Inspects HTTP/HTTPS endpoints for status code, headers, title, server, cookies, and tech indicators"
}

func (c *HTTPCollector) Supports(target domain.Target) bool {
	switch target.Type {
	case domain.TargetDomain, domain.TargetHostname, domain.TargetIPv4, domain.TargetIPv6, domain.TargetURL:
		return true
	default:
		return false
	}
}

type endpointProbe struct {
	scheme string
	port   int
}

func (c *HTTPCollector) Run(ctx context.Context, target domain.Target, opts CollectorOptions) ([]ResultObservation, error) {
	now := time.Now().UTC()
	var observations []ResultObservation

	host := target.NormalizedValue
	if target.Type == domain.TargetURL {
		trimmed := strings.TrimPrefix(host, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		parts := strings.Split(trimmed, "/")
		host = strings.Split(parts[0], ":")[0]
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	probes := []endpointProbe{
		{scheme: "http", port: 80},
		{scheme: "https", port: 443},
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, probe := range probes {
		select {
		case <-ctx.Done():
			return observations, ctx.Err()
		default:
		}

		urlStr := fmt.Sprintf("%s://%s:%d/", probe.scheme, host, probe.port)
		if probe.port == 80 && probe.scheme == "http" {
			urlStr = fmt.Sprintf("http://%s/", host)
		} else if probe.port == 443 && probe.scheme == "https" {
			urlStr = fmt.Sprintf("https://%s/", host)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			continue
		}

		userAgent := opts.UserAgent
		if userAgent == "" {
			userAgent = "Falcon-ToolKit/4.0.0 (Authorized Network Assessment)"
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()

		var title string
		if matches := titleRegex.FindSubmatch(bodyBytes); len(matches) > 1 {
			title = strings.TrimSpace(string(matches[1]))
			title = strings.ReplaceAll(title, "\n", " ")
			title = strings.ReplaceAll(title, "\r", "")
		}

		serverHeader := resp.Header.Get("Server")
		xPoweredBy := resp.Header.Get("X-Powered-By")
		contentType := resp.Header.Get("Content-Type")

		hdrMap := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				hdrMap[k] = v[0]
			}
		}

		tech := ""
		version := ""

		idRes := protocol.NewIdentifier().Identify(protocol.ProbeContext{
			Port:       probe.port,
			Headers:    hdrMap,
			StatusCode: resp.StatusCode,
			HTMLTitle:  title,
		})
		if idRes.Technology != "" {
			tech = idRes.Technology
			version = idRes.Version
		} else if serverHeader != "" {
			parts := strings.SplitN(serverHeader, "/", 2)
			tech = parts[0]
			if len(parts) > 1 {
				version = strings.Split(parts[1], " ")[0]
			}
		} else if xPoweredBy != "" {
			parts := strings.SplitN(xPoweredBy, "/", 2)
			tech = parts[0]
			if len(parts) > 1 {
				version = strings.Split(parts[1], " ")[0]
			}
		}

		var cookieNames []string
		for _, cookie := range resp.Cookies() {
			flags := ""
			if cookie.Secure {
				flags += "Secure;"
			}
			if cookie.HttpOnly {
				flags += "HttpOnly;"
			}
			cookieNames = append(cookieNames, fmt.Sprintf("%s(%s)", cookie.Name, flags))
		}

		meta := map[string]string{
			"url":            urlStr,
			"status_code":    fmt.Sprintf("%d", resp.StatusCode),
			"http_version":   resp.Proto,
			"server":         serverHeader,
			"content_type":   contentType,
			"content_length": fmt.Sprintf("%d", resp.ContentLength),
		}
		if title != "" {
			meta["title"] = title
		}
		if xPoweredBy != "" {
			meta["x_powered_by"] = xPoweredBy
		}
		if len(cookieNames) > 0 {
			meta["cookies"] = strings.Join(cookieNames, ", ")
		}

		serviceName := "http"
		if probe.scheme == "https" {
			serviceName = "https"
		}

		svcObs := observation.ServiceObservation{
			Protocol:    "tcp",
			Port:        probe.port,
			State:       domain.ServiceStateOpen,
			ServiceName: serviceName,
			Technology:  tech,
			Version:     version,
			Description: fmt.Sprintf("HTTP %d, Title: %s, Server: %s", resp.StatusCode, title, serverHeader),
		}

		obs := ResultObservation{
			Collector:  c.Name(),
			SourceID:   fmt.Sprintf("http-%s-%d", host, probe.port),
			Target:     target,
			Timestamp:  now,
			Confidence: domain.ConfidenceHigh,
			Kind:       "http",
			Host: &observation.HostObservation{
				IPAddress:  host,
				ObservedAt: now,
				SourceID:   c.Name(),
				Services:   []observation.ServiceObservation{svcObs},
				Tags:       []string{probe.scheme, fmt.Sprintf("http-%d", resp.StatusCode)},
			},
			Metadata: meta,
			RawData:  fmt.Sprintf("HTTP %s -> %d %s (Server: %s, Title: %s)", urlStr, resp.StatusCode, resp.Status, serverHeader, title),
		}
		observations = append(observations, obs)
	}

	return observations, nil
}
