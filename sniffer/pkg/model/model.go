package model

import "time"

// Packet represents a raw captured packet
// 原始数据包
type Packet struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Length     int       `json:"length"`
	CaptureLen int       `json:"capture_len"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   string    `json:"protocol"`   // TCP, UDP, ICMP, etc.
	Data       []byte    `json:"-"`          // Raw packet data
	LayerInfo  string    `json:"layer_info"` // Layer summary
}

// FiveTuple represents the 5-tuple for session identification
// 五元组
type FiveTuple struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// String returns a string representation of the 5-tuple
func (ft FiveTuple) String() string {
	return ft.SrcIP + ":" + ft.DstIP + ":" + ft.Protocol
}

// Session represents a parsed protocol session
// 会话（派生数据）
type Session struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	FiveTuple   FiveTuple `json:"five_tuple"`
	Type        string    `json:"type"`                  // DNS, HTTP, ICMP
	Domain      string    `json:"domain,omitempty"`      // For DNS/HTTP
	QueryType   string    `json:"query_type,omitempty"`  // For DNS
	ResponseIP  string    `json:"response_ip,omitempty"` // For DNS
	Method      string    `json:"method,omitempty"`      // For HTTP
	Path        string    `json:"path,omitempty"`        // For HTTP
	StatusCode  int       `json:"status_code,omitempty"` // For HTTP
	Host        string    `json:"host,omitempty"`        // For HTTP
	UserAgent   string    `json:"user_agent,omitempty"`  // For HTTP
	ICMPType    uint8     `json:"icmp_type,omitempty"`   // For ICMP
	ICMPCode    uint8     `json:"icmp_code,omitempty"`   // For ICMP
	ICMPSeq     uint16    `json:"icmp_seq,omitempty"`    // For ICMP
	PayloadSize int       `json:"payload_size"`
	TTL         time.Time `json:"ttl"` // Expiration time
}

// Metrics represents real-time capture metrics
// 实时指标
type Metrics struct {
	Timestamp      time.Time `json:"timestamp"`
	Interface      string    `json:"interface"`
	IsCapturing    bool      `json:"is_capturing"`
	IsPaused       bool      `json:"is_paused"`
	PacketsTotal   int64     `json:"packets_total"`
	PacketsDropped int64     `json:"packets_dropped"`
	BytesTotal     int64     `json:"bytes_total"`
	PacketsPerSec  float64   `json:"packets_per_sec"`
	BytesPerSec    float64   `json:"bytes_per_sec"`
	RawCount       int       `json:"raw_count"`
	DNSCount       int       `json:"dns_count"`
	HTTPCount      int       `json:"http_count"`
	ICMPCount      int       `json:"icmp_count"`
}

// Interface represents a network interface
// 网络接口
type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
	IsPhysical  bool     `json:"is_physical"`
	IsLoopback  bool     `json:"is_loopback"`
	IsUp        bool     `json:"is_up"`
}

// ExportRequest represents a PCAP export request
// 导出请求
type ExportRequest struct {
	StartTime int64  `json:"start_time"` // Unix timestamp
	EndTime   int64  `json:"end_time"`   // Unix timestamp
	Filter    string `json:"filter"`     // BPF filter
}

// TableType represents different data tables
// 表类型
type TableType string

const (
	TableRaw  TableType = "raw"
	TableDNS  TableType = "dns"
	TableHTTP TableType = "util"
	TableICMP TableType = "icmp"
)
