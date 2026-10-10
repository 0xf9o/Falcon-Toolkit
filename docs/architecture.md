# وثيقة المواصفات المعمارية الشاملة: Falcon Toolkit
**Enterprise Network Reachability, Segmentation & Attack-Surface Platform**
**اللغة المستهدفة:** Go (Golang) | **النمط التشغيلي:** Interactive REPL / Live TUI & Distributed Mesh

---

## 1. الرؤية الهندسية للمشروع (Architectural Vision)
منصة **Falcon Toolkit** هي إطار عمل متقدم وهجين مخصص لفرق الأمن السيبراني (Red & Purple Teams) ومهندسي أمان البنية التحتية، يهدف إلى تدقيق وتوثيق ومحاكاة كفاءة العزل الشبكي (Segmentation & Micro-segmentation)، وتحليل مسارات الحركة المحتملة (Lateral Movement & Reachability)، واكتشاف نقاط الاختناق (Chokepoints) والفجوات الأمنية في الجدران النارية والشبكات السحابية والهجينة، ضمن حزمة برمجية موحدة وعالية الأداء.

---

## 2. تفصيل المحركات والوحدات الوظيفية (Core Subsystems)

### 2.1. محرك الاستشعار الصامت (Passive Recon & Sniffing)
* **LLMNR / mDNS / NetBIOS Listener:** التقاط طلبات البث لاستكشاف أسماء الأجهزة وعناوينها تلقائياً دون توليد أي حركة مرور نشطة.
* **Passive Traffic Fingerprinting:** تحليل قيم TTL وTCP Window Size للحزم المارة واستنتاج أنظمة التشغيل وحجم الاتصالات بين القطاعات.
* **CDP / LLDP Sniffing:** تفكيك حزم إعلانات أجهزة الربط لتحديد رقم الـ VLAN، اسم السويتش، ورقم المنفذ المتصل به المضيف.

### 2.2. محرك كشف التجزئة الدقيقة للويب والخدمات (Micro-Service Fingerprinter)
* **TLS Certificate & FQDN Extraction:** قراءة شهادات SSL/TLS لاستخراج أسماء النطاقات الداخلية (Internal FQDNs) وتحديد البنية التحتية.
* **Admin Surface Identification:** كشف واجهات الإدارة الحساسة غير المعزولة (مثل Kubernetes API, vSphere, Proxmox, Jenkins, IPMI/iLO).

### 2.3. محرك تدقيق الأنفاق والعبور (Pivoting & Egress Validator)
* **Tunnel MTU & Fragmentation Prober:** قياس الـ MTU الفعلي عبر المسارات المفتوحة لضمان استقرار أنفاق SOCKS5 أو WireGuard عبر النطاقات المختلفة.
* **Exfiltration Feasibility Check:** فحص إمكانية تمرير البيانات عبر استعلامات DNS أو حزم ICMP لتحديد ما إذا كان الجدار الناري يطبق التفتيش العميق (DPI).
* **Reverse NAT & Multipath Detection:** اكتشاف تعدد مسارات الخروج (ECMP) واختبار تساهل الرقابة على ترافيك الـ Egress الخارجي.

### 2.4. محرك استنتاج القواعد والمحاكي التنبؤي (Firewall Diff & Simulator)
* **Stateful vs. Stateless Detection:** إرسال حزم TCP بأعلام مختلفة (SYN, ACK, FIN, NULL) للتحقق مما إذا كان الجدار الناري يتتبع حالة الاتصال أم يطبق مجرد قوائم ACL ساكنة.
* **Policy Rule Inferrer:** استنتاج القواعد المعاكسة؛ مثل قيود المنفذ المصدر (Source Port 53 Bypass).
* **What-If Policy Simulator:** تطبيق خوارزميات قطع الشبكات (Min-Cut) داخل الـ REPL لتوقع أثر إضافة قاعدة حظر معينة على المسارات البديلة قبل التنفيذ الفعلي.

### 2.5. محرك التخفي وضبط البصمة (OpSec & Evasion Module)
* **TCP Options & Window Jittering:** توليد ترويسات بروتوكولية شبه حقيقية تحاكي المتصفحات الشائعة لتجنب الرصد القائم على التوقيعات النمطية.
* **Packet Dispersion:** توزيع الحزم زمنياً وتفريقها عبر مسارات مختلفة (Round-Robin Target Rotation) لمنع أجهزة الـ IDS/IPS من تجميعها كنمط فحص موحد.

### 2.6. نظام البرمجة النصية والأتمتة (Embedded Scripting Engine)
* **Tengo / Lua Embedded Runtime:** تشغيل سكربتات فحص وسيناريوهات منطقية متقدمة داخل الذاكرة دون الحاجة لإعادة تجميع الكود المصدري.
* **Pre-flight Profiles:** توفير سيناريوهات جاهزة مثل `zero-trust-audit` و `active-directory-reachability`.

### 2.7. شبكة الحساسات الموزعة (Distributed Multi-Vantage Mesh)
* **gRPC / mTLS Control Plane:** نشر وكلاء (Probes) في شبكات فرعية مختلفة وإدارتها مركزياً عبر جلسات اتصال مشفرة ومصادق عليها بالكامل.
* **Bidirectional Reachability Matrix:** التنسيق بين الحساسات لإرسال واستقبال الحزم بين عدة نطاقات متزامنة لكشف التوجيه غير المتماثل (Asymmetric Routing).

### 2.8. تدقيق التوجيه الديناميكي والبيئات الهجينة والسحابية
* **OSPF & BGP Passive Listener:** استخراج جداول التوجيه المؤسسية ورصد تسريب المسارات (Route Leaking) نحو الشبكات المعزولة.
* **Hybrid Cloud Bridge Auditor:** فحص مسارات الاتصال المباشر (DirectConnect / ExpressRoute) والتحقق من حظر الوصول لعناوين الـ Metadata الحساسة (`169.254.169.254`).

### 2.9. تدقيق طبقة النواة وعزل الحاويات (eBPF / XDP Probing)
* **Kernel Flow Tracing:** استخدام مكتبات eBPF للتعامل السريع مع حركة المرور دون تحميل الذاكرة أو المعالج أعباء التبديل بين الطبقات (Context Switching).
* **Kubernetes NetworkPolicy Audit:** مراقبة الاتصال بين حاويات التطبيقات وتدقيق سياسات العزل الداخلية في البنية التحتية للحاويات.

### 2.10. تدقيق طبقة الهوية والتحكم بالوصول (Identity & NAC Auditing)
* **Active Directory & RPC Interrogator:** ربط فحص المنافذ بمدى كشف خدمات النطاق (Kerberos TGS / MS-RPC Endpoint Mapping) نحو شبكات الموظفين أو الضيوف.
* **802.1X & NAC Posture Check:** اختبار متانة التحقق من منافذ الشبكة الفيزيائية والكشف عن إمكانية تجاوز الـ MAC Authentication Bypass (MAB).

### 2.11. خوارزميات المخططات ونقاط الاختناق (Graph Theory & Chokepoints)
* **Chokepoint Centrality:** احتساب مراكز الثقل في المخطط الشبكي وتحديد السويتشات أو الجدران النارية التي تمثل نقاط ضعف حرجة.
* **Blast Radius Metric:** قياس كمي لحجم الضرر والأصول المعرضة للخطر في حال النفاذ لأي قطاع شبكي محدد.

---

## 3. نماذج البيانات الأساسية (Data Models in Go)

```go
package schema

import "time"

// ReachabilityState يحدد حالة المسار الشبكي
type ReachabilityState string

const (
    StateOpen       ReachabilityState = "REACHABLE"
    StateFiltered   ReachabilityState = "FILTERED"
    StateAsymmetric ReachabilityState = "ASYMMETRIC_LEAK"
    StateIsolated   ReachabilityState = "STRICTLY_ISOLATED"
)

// ServiceProbeResult يمثل تفاصيل فحص خدمة معينة
type ServiceProbeResult struct {
    Protocol    string            `json:"protocol"`
    Port        int               `json:"port"`
    ServiceName string            `json:"service_name"`
    Banner      string            `json:"banner,omitempty"`
    TLSDetails  map[string]string `json:"tls_details,omitempty"`
    State       ReachabilityState `json:"state"`
    LatencyMs   int64             `json:"latency_ms"`
}

// SubnetPosture يمثل وضع العزل لنطاق فرعي
type SubnetPosture struct {
    SubnetCIDR     string               `json:"subnet_cidr"`
    VLANID         int                  `json:"vlan_id,omitempty"`
    SwitchPort     string               `json:"switch_port,omitempty"`
    ExposedHosts   []string             `json:"exposed_hosts"`
    ProbedServices []ServiceProbeResult `json:"probed_services"`
    BlastScore     float64              `json:"blast_score"` // 0.0 إلى 10.0
    Compliance     string               `json:"compliance"`  // PASS / FAIL
}

// SessionEnvironment يحتوي على كامل البيانات وسياق العمل اللحظي
type SessionEnvironment struct {
    SessionID    string                   `json:"session_id"`
    StartTime    time.Time                `json:"start_time"`
    ActiveCIDR   string                   `json:"active_cidr"`
    TargetScopes []string                 `json:"target_scopes"`
    Postures     map[string]SubnetPosture `json:"postures"`
}
```
