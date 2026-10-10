package graph

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/falcon-toolkit/falcon/internal/schema"
)

// CriticalityWeight maps critical port numbers to security severity multipliers.
func CriticalityWeight(port int) float64 {
	switch port {
	case 88, 389, 636: // Active Directory / Kerberos / LDAPS
		return 3.5
	case 445: // SMB / Lateral Movement Vector
		return 3.0
	case 3389, 5985, 5986: // RDP / WinRM Administrative Access
		return 2.5
	case 1433, 1521, 3306, 5432, 6379, 27017: // Databases
		return 2.5
	case 502, 102, 4840, 44818: // OT / Industrial Control Protocols
		return 4.0
	case 22, 23: // SSH / Telnet Management
		return 2.0
	case 80, 443, 8080, 8443: // Web Services
		return 1.2
	default:
		return 1.0
	}
}

// CalculateBlastScore computes an objective 0.0 - 10.0 risk and blast score for a subnet.
func CalculateBlastScore(posture schema.SubnetPosture) float64 {
	if len(posture.ProbedServices) == 0 && len(posture.ExposedHosts) == 0 {
		return 0.0
	}

	var sumWeights float64
	openCount := 0

	for _, svc := range posture.ProbedServices {
		if svc.State == schema.StateOpen {
			openCount++
			weight := CriticalityWeight(svc.Port)
			sumWeights += weight
		}
	}

	// Proximity multiplier based on host density
	hostCount := len(posture.ExposedHosts)
	if hostCount == 0 {
		hostCount = 1
	}
	proximity := 1.0 + (math.Log10(float64(hostCount)) * 0.5)

	rawScore := (sumWeights * 0.6) * proximity
	if rawScore > 10.0 {
		return 10.0
	}
	return math.Round(rawScore*10) / 10
}

// SimulationRule represents an in-memory hypothetical access control rule.
type SimulationRule struct {
	Action      string `json:"action"` // DENY or PERMIT
	SourceCIDR  string `json:"source_cidr"`
	DestCIDR    string `json:"dest_cidr"`
	Port        int    `json:"port"`
	Description string `json:"description"`
}

// SimulationResult captures before and after metrics of a What-If policy test.
type SimulationResult struct {
	Rule             SimulationRule `json:"rule"`
	InitialEdges     int            `json:"initial_edges"`
	RemainingEdges   int            `json:"remaining_edges"`
	DroppedEdges     int            `json:"dropped_edges"`
	InitialScore     float64        `json:"initial_blast_score"`
	MitigatedScore   float64        `json:"mitigated_blast_score"`
	MitigationEffect string         `json:"mitigation_effect"`
}

// SimulateBlockRule clones the graph in-memory, applies the simulated drop, and recalculates impact.
func (g *Graph) SimulateBlockRule(rule SimulationRule, currentPosture schema.SubnetPosture) SimulationResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	initialEdges := len(g.edges)
	droppedCount := 0

	var filteredServices []schema.ServiceProbeResult
	for _, svc := range currentPosture.ProbedServices {
		if svc.State == schema.StateOpen && (rule.Port == 0 || svc.Port == rule.Port) {
			droppedCount++
			// Dropped in simulation
			svcCopy := svc
			svcCopy.State = schema.StateFiltered
			filteredServices = append(filteredServices, svcCopy)
		} else {
			filteredServices = append(filteredServices, svc)
		}
	}

	simulatedPosture := currentPosture
	simulatedPosture.ProbedServices = filteredServices

	initialScore := CalculateBlastScore(currentPosture)
	newScore := CalculateBlastScore(simulatedPosture)

	effect := fmt.Sprintf("Reduces blast radius by %.1f points (%d exposed vectors severed)",
		initialScore-newScore, droppedCount)

	return SimulationResult{
		Rule:             rule,
		InitialEdges:     initialEdges,
		RemainingEdges:   initialEdges - droppedCount,
		DroppedEdges:     droppedCount,
		InitialScore:     initialScore,
		MitigatedScore:   newScore,
		MitigationEffect: effect,
	}
}

// BuildSubnetGraph constructs an analytical graph from evaluated postures.
func BuildSubnetGraph(postures map[string]schema.SubnetPosture) *Graph {
	g := New()

	for cidr, post := range postures {
		subnetNodeID := fmt.Sprintf("NET-%s", strings.ReplaceAll(cidr, "/", "-"))
		g.AddNode(&Node{
			ID:    subnetNodeID,
			Type:  NodeNetwork,
			Label: fmt.Sprintf("Subnet %s (Score: %.1f)", cidr, post.BlastScore),
			Properties: map[string]string{
				"cidr":        cidr,
				"blast_score": fmt.Sprintf("%.1f", post.BlastScore),
			},
		})

		for _, host := range post.ExposedHosts {
			hostNodeID := fmt.Sprintf("HOST-%s", strings.ReplaceAll(host, ".", "-"))
			g.AddNode(&Node{
				ID:    hostNodeID,
				Type:  NodeAsset,
				Label: host,
				Properties: map[string]string{
					"ip": host,
				},
			})

			g.AddEdge(&Edge{
				ID:       fmt.Sprintf("e_%s_%s", subnetNodeID, hostNodeID),
				SourceID: subnetNodeID,
				TargetID: hostNodeID,
				Type:     "contains",
			})

			for _, svc := range post.ProbedServices {
				if svc.State == schema.StateOpen {
					svcNodeID := fmt.Sprintf("SVC-%s-%d", hostNodeID, svc.Port)
					g.AddNode(&Node{
						ID:    svcNodeID,
						Type:  NodeService,
						Label: fmt.Sprintf("%s (%d/tcp)", svc.ServiceName, svc.Port),
						Properties: map[string]string{
							"port":     strconv.Itoa(svc.Port),
							"protocol": svc.Protocol,
						},
					})
					g.AddEdge(&Edge{
						ID:       fmt.Sprintf("e_%s_%s", hostNodeID, svcNodeID),
						SourceID: hostNodeID,
						TargetID: svcNodeID,
						Type:     "exposes",
					})
				}
			}
		}
	}

	return g
}
