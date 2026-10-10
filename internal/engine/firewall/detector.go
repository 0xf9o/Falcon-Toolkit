package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// FirewallBehavior indicates how the network boundary handles unsolicited packets.
type FirewallBehavior string

const (
	BehaviorStatefulDrop   FirewallBehavior = "STATEFUL_DROP"
	BehaviorStatefulReject FirewallBehavior = "STATEFUL_REJECT"
	BehaviorStatelessACL   FirewallBehavior = "STATELESS_ACL"
	BehaviorPermissive     FirewallBehavior = "PERMISSIVE"
	BehaviorUnknown        FirewallBehavior = "UNKNOWN"
)

// PolicyAssessment captures firewall rule behavior and potential bypass vectors.
type PolicyAssessment struct {
	TargetHost       string           `json:"target_host"`
	TargetPort       int              `json:"target_port"`
	Behavior         FirewallBehavior `json:"behavior"`
	SourcePort53Pass bool             `json:"source_port_53_bypass"`
	SourcePort88Pass bool             `json:"source_port_88_bypass"`
	Details          string           `json:"details"`
}

// Detector evaluates stateful connection tracking and source port bypass flaws.
type Detector struct {
	Timeout time.Duration
}

// NewDetector creates a new firewall policy analyzer.
func NewDetector(timeout time.Duration) *Detector {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Detector{Timeout: timeout}
}

// AnalyzePort evaluates firewall behavior against a specific host and port.
func (d *Detector) AnalyzePort(ctx context.Context, host string, port int) PolicyAssessment {
	assessment := PolicyAssessment{
		TargetHost: host,
		TargetPort: port,
		Behavior:   BehaviorUnknown,
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 1. Standard Connect Probe
	dialer := &net.Dialer{Timeout: d.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		assessment.Behavior = BehaviorPermissive
		assessment.Details = "Port is openly reachable without firewall filtering"
		return assessment
	}

	// Classify drop vs rejection
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		assessment.Behavior = BehaviorStatefulDrop
		assessment.Details = "Packets silently dropped (Stateful Drop / Silent Filter)"
	} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
		assessment.Behavior = BehaviorStatefulReject
		assessment.Details = "TCP RST returned immediately (Port Closed or Active Firewall Reject)"
	} else {
		assessment.Behavior = BehaviorStatelessACL
		assessment.Details = fmt.Sprintf("ICMP unreachable or ACL violation: %v", err)
	}

	// 2. Test Source Port 53 (DNS) bypass
	assessment.SourcePort53Pass = d.testSourcePortBind(ctx, host, port, 53)

	// 3. Test Source Port 88 (Kerberos) bypass
	assessment.SourcePort88Pass = d.testSourcePortBind(ctx, host, port, 88)

	if assessment.SourcePort53Pass || assessment.SourcePort88Pass {
		assessment.Details += " | CRITICAL: Permitted via trusted source port bypass!"
	}

	return assessment
}

func (d *Detector) testSourcePortBind(ctx context.Context, host string, port int, srcPort int) bool {
	localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", srcPort))
	if err != nil {
		// May require root/admin to bind < 1024, if unable, skip
		return false
	}

	dialer := &net.Dialer{
		Timeout:   d.Timeout,
		LocalAddr: localAddr,
	}

	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}
