package protocol

import (
	"regexp"

	"github.com/falcon-toolkit/falcon/internal/domain"
)

// TechCategory classifies the role of identified software.
type TechCategory string

const (
	CatWebServer      TechCategory = "web_server"
	CatDatabase       TechCategory = "database"
	CatRemoteAccess   TechCategory = "remote_access"
	CatDirectory      TechCategory = "directory_service"
	CatContainer      TechCategory = "container_orchestration"
	CatMail           TechCategory = "mail_server"
	CatFileTransfer   TechCategory = "file_transfer"
	CatOTICS          TechCategory = "ot_ics"
	CatInfrastructure TechCategory = "infrastructure"
)

// Signature defines an evidence-driven fingerprint pattern.
type Signature struct {
	Name            string
	Protocol        string
	Category        TechCategory
	PortHints       []int
	BannerRegex     *regexp.Regexp
	HeaderKey       string
	HeaderRegex     *regexp.Regexp
	TitleRegex      *regexp.Regexp
	TLSSubjectRegex *regexp.Regexp
	ResponseRegex   *regexp.Regexp
	VersionRegex    *regexp.Regexp
	Confidence      domain.ConfidenceLevel
	IsOT            bool
}

// BuiltinSignatures returns the authoritative technology and protocol fingerprint library.
func BuiltinSignatures() []Signature {
	return []Signature{
		// ---------------- Web Servers & APIs ----------------
		{
			Name:         "nginx",
			Protocol:     "HTTP",
			Category:     CatWebServer,
			PortHints:    []int{80, 443, 8080, 8443},
			HeaderKey:    "Server",
			HeaderRegex:  regexp.MustCompile(`(?i)nginx(?:/([0-9.]+))?`),
			VersionRegex: regexp.MustCompile(`(?i)nginx/([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "Apache",
			Protocol:     "HTTP",
			Category:     CatWebServer,
			PortHints:    []int{80, 443, 8080, 8443},
			HeaderKey:    "Server",
			HeaderRegex:  regexp.MustCompile(`(?i)Apache(?:/([0-9.]+))?`),
			VersionRegex: regexp.MustCompile(`(?i)Apache/([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "Microsoft-IIS",
			Protocol:     "HTTP",
			Category:     CatWebServer,
			PortHints:    []int{80, 443, 8080, 8443},
			HeaderKey:    "Server",
			HeaderRegex:  regexp.MustCompile(`(?i)Microsoft-IIS(?:/([0-9.]+))?`),
			VersionRegex: regexp.MustCompile(`(?i)Microsoft-IIS/([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "Docker API",
			Protocol:     "HTTP",
			Category:     CatContainer,
			PortHints:    []int{2375, 2376},
			HeaderKey:    "Server",
			HeaderRegex:  regexp.MustCompile(`(?i)Docker(?:/([0-9.]+))?`),
			TitleRegex:   regexp.MustCompile(`(?i)Docker`),
			VersionRegex: regexp.MustCompile(`(?i)Docker/([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:            "Kubernetes API",
			Protocol:        "HTTPS",
			Category:        CatContainer,
			PortHints:       []int{6443, 8443},
			TLSSubjectRegex: regexp.MustCompile(`(?i)kube-apiserver|kubernetes`),
			TitleRegex:      regexp.MustCompile(`(?i)Kubernetes`),
			Confidence:      domain.ConfidenceHigh,
		},

		// ---------------- Remote Access & Shell ----------------
		{
			Name:         "OpenSSH",
			Protocol:     "SSH",
			Category:     CatRemoteAccess,
			PortHints:    []int{22, 2222},
			BannerRegex:  regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH[_-]([0-9.p]+)`),
			VersionRegex: regexp.MustCompile(`(?i)OpenSSH[_-]([0-9.p]+)`),
			Confidence:   domain.ConfidenceObserved,
		},
		{
			Name:         "Dropbear",
			Protocol:     "SSH",
			Category:     CatRemoteAccess,
			PortHints:    []int{22},
			BannerRegex:  regexp.MustCompile(`(?i)SSH-2\.0-dropbear[_-]([0-9.]+)`),
			VersionRegex: regexp.MustCompile(`(?i)dropbear[_-]([0-9.]+)`),
			Confidence:   domain.ConfidenceObserved,
		},
		{
			Name:        "Microsoft Terminal Services",
			Protocol:    "RDP",
			Category:    CatRemoteAccess,
			PortHints:   []int{3389},
			BannerRegex: regexp.MustCompile(`(?i)rdp|ms-wbt`),
			Confidence:  domain.ConfidenceHigh,
		},
		{
			Name:        "Linux telnetd",
			Protocol:    "Telnet",
			Category:    CatRemoteAccess,
			PortHints:   []int{23},
			BannerRegex: regexp.MustCompile(`(?i)telnet|login:`),
			Confidence:  domain.ConfidenceHigh,
		},

		// ---------------- Databases ----------------
		{
			Name:         "PostgreSQL",
			Protocol:     "PostgreSQL",
			Category:     CatDatabase,
			PortHints:    []int{5432},
			BannerRegex:  regexp.MustCompile(`(?i)PostgreSQL|FATAL.*database`),
			VersionRegex: regexp.MustCompile(`(?i)PostgreSQL\s+([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "MySQL",
			Protocol:     "MySQL",
			Category:     CatDatabase,
			PortHints:    []int{3306},
			BannerRegex:  regexp.MustCompile(`(?i)([0-9.]+-MariaDB|[0-9.]+-log|[0-9.]+mysql)`),
			VersionRegex: regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "Redis",
			Protocol:     "Redis",
			Category:     CatDatabase,
			PortHints:    []int{6379},
			BannerRegex:  regexp.MustCompile(`(?i)\+PONG|-NOAUTH|-ERR|redis_version:([0-9.]+)`),
			VersionRegex: regexp.MustCompile(`(?i)redis_version:([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:        "Microsoft SQL Server",
			Protocol:    "MSSQL",
			Category:    CatDatabase,
			PortHints:   []int{1433},
			BannerRegex: regexp.MustCompile(`(?i)MSSQL|SQL Server`),
			Confidence:  domain.ConfidenceHigh,
		},

		// ---------------- File & Mail ----------------
		{
			Name:         "vsftpd",
			Protocol:     "FTP",
			Category:     CatFileTransfer,
			PortHints:    []int{21},
			BannerRegex:  regexp.MustCompile(`(?i)vsftpd\s*([0-9.]+)?`),
			VersionRegex: regexp.MustCompile(`(?i)vsftpd\s*([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:         "ProFTPD",
			Protocol:     "FTP",
			Category:     CatFileTransfer,
			PortHints:    []int{21},
			BannerRegex:  regexp.MustCompile(`(?i)ProFTPD\s*([0-9.]+)?`),
			VersionRegex: regexp.MustCompile(`(?i)ProFTPD\s*([0-9.]+)`),
			Confidence:   domain.ConfidenceHigh,
		},
		{
			Name:        "Postfix",
			Protocol:    "SMTP",
			Category:    CatMail,
			PortHints:   []int{25, 465, 587},
			BannerRegex: regexp.MustCompile(`(?i)ESMTP\s+Postfix`),
			Confidence:  domain.ConfidenceHigh,
		},
		{
			Name:        "Microsoft Exchange",
			Protocol:    "SMTP",
			Category:    CatMail,
			PortHints:   []int{25, 465, 587},
			BannerRegex: regexp.MustCompile(`(?i)Microsoft\s+ESMTP\s+MAIL\s+Service`),
			Confidence:  domain.ConfidenceHigh,
		},

		// ---------------- Directory & Infrastructure ----------------
		{
			Name:        "Active Directory LDAP",
			Protocol:    "LDAP",
			Category:    CatDirectory,
			PortHints:   []int{389, 636, 3268},
			BannerRegex: regexp.MustCompile(`(?i)Active\s*Directory|NTLMSSP`),
			Confidence:  domain.ConfidenceHigh,
		},
		{
			Name:        "Microsoft SMB",
			Protocol:    "SMB",
			Category:    CatInfrastructure,
			PortHints:   []int{445, 139},
			BannerRegex: regexp.MustCompile(`(?i)SMB|Windows|Samba`),
			Confidence:  domain.ConfidenceHigh,
		},
		{
			Name:         "BIND",
			Protocol:     "DNS",
			Category:     CatInfrastructure,
			PortHints:    []int{53},
			BannerRegex:  regexp.MustCompile(`(?i)BIND`),
			VersionRegex: regexp.MustCompile(`(?i)BIND\s*([0-9.a-zA-Z]+)`),
			Confidence:   domain.ConfidenceHigh,
		},

		// ---------------- OT / Industrial Control (ICS) ----------------
		{
			Name:          "Schneider Modbus/TCP",
			Protocol:      "Modbus/TCP",
			Category:      CatOTICS,
			PortHints:     []int{502},
			BannerRegex:   regexp.MustCompile(`(?i)modbus|schneider|quantum|premium`),
			ResponseRegex: regexp.MustCompile(`(?i)modbus`),
			Confidence:    domain.ConfidenceObserved,
			IsOT:          true,
		},
		{
			Name:          "Siemens S7 Protocol",
			Protocol:      "S7",
			Category:      CatOTICS,
			PortHints:     []int{102},
			BannerRegex:   regexp.MustCompile(`(?i)s7|siemens|simatic|cotp`),
			ResponseRegex: regexp.MustCompile(`(?i)s7|cotp`),
			Confidence:    domain.ConfidenceObserved,
			IsOT:          true,
		},
		{
			Name:          "OPC UA Server",
			Protocol:      "OPC UA",
			Category:      CatOTICS,
			PortHints:     []int{4840},
			BannerRegex:   regexp.MustCompile(`(?i)opc(?:\.tcp)?|opc-ua`),
			ResponseRegex: regexp.MustCompile(`(?i)opc`),
			Confidence:    domain.ConfidenceObserved,
			IsOT:          true,
		},
		{
			Name:          "DNP3 Protocol",
			Protocol:      "DNP3",
			Category:      CatOTICS,
			PortHints:     []int{20000},
			BannerRegex:   regexp.MustCompile(`(?i)dnp3`),
			ResponseRegex: regexp.MustCompile(`(?i)dnp3`),
			Confidence:    domain.ConfidenceObserved,
			IsOT:          true,
		},
		{
			Name:          "EtherNet/IP",
			Protocol:      "EtherNet/IP",
			Category:      CatOTICS,
			PortHints:     []int{44818},
			BannerRegex:   regexp.MustCompile(`(?i)ethernet/ip|enip|cip`),
			ResponseRegex: regexp.MustCompile(`(?i)enip|cip`),
			Confidence:    domain.ConfidenceObserved,
			IsOT:          true,
		},
	}
}
