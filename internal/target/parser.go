package target

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

var (
	hostnameLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
)

// ParseTarget parses and normalizes a user-supplied target input into a strongly-typed domain.Target.
func ParseTarget(rawInput string) (*domain.Target, error) {
	trimmed := strings.TrimSpace(rawInput)
	trimmed = strings.Trim(trimmed, `"'`)
	if trimmed == "" {
		return nil, fmt.Errorf("target value cannot be empty")
	}

	tType, normVal, meta, err := ClassifyAndNormalize(trimmed)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &domain.Target{
		Input:           trimmed,
		NormalizedValue: normVal,
		Value:           normVal,
		Type:            tType,
		Scope:           domain.TargetInScope,
		Status:          domain.TargetStatusPending,
		Metadata:        meta,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// ClassifyAndNormalize identifies the target type, canonical value, and extracted metadata.
func ClassifyAndNormalize(input string) (domain.TargetType, string, map[string]string, error) {
	meta := make(map[string]string)

	// 1. URL Check (http:// or https://)
	if strings.HasPrefix(strings.ToLower(input), "http://") || strings.HasPrefix(strings.ToLower(input), "https://") {
		parsedURL, err := url.Parse(input)
		if err != nil {
			return "", "", nil, fmt.Errorf("invalid URL target %q: %w", input, err)
		}
		if parsedURL.Host == "" {
			return "", "", nil, fmt.Errorf("invalid URL target %q: missing host", input)
		}

		scheme := strings.ToLower(parsedURL.Scheme)
		host := strings.ToLower(parsedURL.Hostname())
		port := parsedURL.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		path := parsedURL.Path
		if path == "" {
			path = "/"
		}

		canonicalURL := fmt.Sprintf("%s://%s", scheme, host)
		if (scheme == "http" && port != "80") || (scheme == "https" && port != "443") {
			canonicalURL = fmt.Sprintf("%s://%s:%s", scheme, host, port)
		}
		canonicalURL += path
		if parsedURL.RawQuery != "" {
			canonicalURL += "?" + parsedURL.RawQuery
		}

		meta["url_scheme"] = scheme
		meta["url_host"] = host
		meta["url_port"] = port
		meta["url_path"] = path

		return domain.TargetURL, canonicalURL, meta, nil
	}

	// 2. CIDR Check (contains '/')
	if strings.Contains(input, "/") {
		ip, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return "", "", nil, fmt.Errorf("invalid CIDR target %q: %w", input, err)
		}

		canonicalCIDR := ipNet.String()
		ones, bits := ipNet.Mask.Size()
		totalIPs := 0
		if bits == 32 {
			hostBits := 32 - ones
			if hostBits < 31 {
				totalIPs = int(math.Pow(2, float64(hostBits)))
			} else {
				totalIPs = math.MaxInt32
			}
		}

		meta["network"] = ipNet.IP.String()
		meta["netmask"] = net.IP(ipNet.Mask).String()
		meta["mask_bits"] = strconv.Itoa(ones)
		meta["total_ips"] = strconv.Itoa(totalIPs)

		if ip.To4() != nil {
			meta["ip_version"] = "v4"
			meta["is_private"] = strconv.FormatBool(ip.IsPrivate())
		} else {
			meta["ip_version"] = "v6"
		}

		return domain.TargetCIDR, canonicalCIDR, meta, nil
	}

	// 3. IP Check (IPv4 or IPv6)
	ip := net.ParseIP(input)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			canonical := ipv4.String()
			meta["ip_version"] = "v4"
			meta["is_private"] = strconv.FormatBool(ipv4.IsPrivate())
			meta["is_loopback"] = strconv.FormatBool(ipv4.IsLoopback())
			return domain.TargetIPv4, canonical, meta, nil
		}

		canonical := ip.String()
		meta["ip_version"] = "v6"
		meta["is_loopback"] = strconv.FormatBool(ip.IsLoopback())
		return domain.TargetIPv6, canonical, meta, nil
	}

	// 4. Hostname / Domain Check
	cleanedHost := strings.ToLower(input)
	// Remove trailing dot if present for root zone
	cleanedHost = strings.TrimSuffix(cleanedHost, ".")

	labels := strings.Split(cleanedHost, ".")
	allValid := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !hostnameLabelRegex.MatchString(label) {
			allValid = false
			break
		}
	}

	if allValid {
		if len(labels) == 1 {
			meta["label_count"] = "1"
			return domain.TargetHostname, cleanedHost, meta, nil
		}
		meta["label_count"] = strconv.Itoa(len(labels))
		meta["tld"] = labels[len(labels)-1]
		return domain.TargetDomain, cleanedHost, meta, nil
	}

	return "", "", nil, fmt.Errorf("unrecognized target format %q: expected IPv4, IPv6, CIDR, domain, hostname, or URL", input)
}

// ExpandCIDR returns a slice of IP addresses contained in the CIDR block, up to maxHosts.
func ExpandCIDR(cidrStr string, maxHosts int) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("CIDR expansion currently only supports IPv4")
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ip4)
	end := (start & mask) | (mask ^ 0xffffffff)

	// If /31 or /32 include all, otherwise skip network and broadcast
	ones, _ := ipNet.Mask.Size()
	var ips []net.IP

	if ones >= 31 {
		for i := start; i <= end; i++ {
			if len(ips) >= maxHosts && maxHosts > 0 {
				break
			}
			curIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(curIP, i)
			ips = append(ips, curIP)
		}
		return ips, nil
	}

	for i := start + 1; i < end; i++ {
		if len(ips) >= maxHosts && maxHosts > 0 {
			break
		}
		curIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(curIP, i)
		ips = append(ips, curIP)
	}

	return ips, nil
}
