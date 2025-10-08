package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"sniffer/pkg/model"
)

var (
	ErrNotDNS   = errors.New("not a DNS packet")
	ErrNotHTTP  = errors.New("not an HTTP packet")
	ErrNotICMP  = errors.New("not an ICMP packet")
	ErrParseErr = errors.New("parse error")
)

// ParsePacket parses a raw packet and extracts basic information
func ParsePacket(data []byte, timestamp time.Time) (*model.Packet, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	pkt := &model.Packet{
		Timestamp:  timestamp,
		Length:     len(data),
		CaptureLen: len(data),
		Data:       data,
		LayerInfo:  "",
	}

	// Extract IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		pkt.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		pkt.SrcIP = ip.SrcIP.String()
		pkt.DstIP = ip.DstIP.String()
		pkt.Protocol = ip.NextHeader.String()
	}

	// Extract transport layer ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pkt.SrcPort = uint16(tcp.SrcPort)
		pkt.DstPort = uint16(tcp.DstPort)
		pkt.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.SrcPort = uint16(udp.SrcPort)
		pkt.DstPort = uint16(udp.DstPort)
		pkt.Protocol = "UDP"
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		pkt.Protocol = "ICMP"
	}

	// Build layer summary
	var layers []string
	for _, layer := range packet.Layers() {
		layers = append(layers, layer.LayerType().String())
	}
	pkt.LayerInfo = strings.Join(layers, " > ")

	return pkt, nil
}

// ParseDNS parses a DNS packet
func ParseDNS(pkt *model.Packet) (*model.Session, error) {
	// DNS typically uses UDP port 53
	if pkt.Protocol != "UDP" || (pkt.SrcPort != 53 && pkt.DstPort != 53) {
		return nil, ErrNotDNS
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)
	
	// Get UDP payload
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, ErrNotDNS
	}

	udp, _ := udpLayer.(*layers.UDP)
	payload := udp.Payload

	// Parse DNS
	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseErr, err)
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: "UDP",
		},
		Type:        "DNS",
		PayloadSize: len(payload),
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour), // 7 days default
	}

	// Extract query information
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		session.Domain = strings.TrimSuffix(q.Name, ".")
		session.QueryType = dns.TypeToString[q.Qtype]
	}

	// Extract answer information (for responses)
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				session.ResponseIP = a.A.String()
				break
			} else if aaaa, ok := rr.(*dns.AAAA); ok {
				session.ResponseIP = aaaa.AAAA.String()
				break
			}
		}
	}

	return session, nil
}

// ParseHTTP parses an HTTP packet (HTTP/1.x only, not HTTPS)
func ParseHTTP(pkt *model.Packet) (*model.Session, error) {
	// HTTP typically uses TCP
	if pkt.Protocol != "TCP" {
		return nil, ErrNotHTTP
	}

	// Common HTTP ports
	isHTTPPort := pkt.SrcPort == 80 || pkt.DstPort == 80 ||
		pkt.SrcPort == 8080 || pkt.DstPort == 8080 ||
		pkt.SrcPort == 8000 || pkt.DstPort == 8000

	if !isHTTPPort {
		return nil, ErrNotHTTP
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)

	// Get TCP payload
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, ErrNotHTTP
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload

	if len(payload) == 0 {
		return nil, ErrNotHTTP
	}

	// Check if it looks like HTTP
	if !isHTTPData(payload) {
		return nil, ErrNotHTTP
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			SrcPort:  pkt.SrcPort,
			DstPort:  pkt.DstPort,
			Protocol: "TCP",
		},
		Type:        "HTTP",
		PayloadSize: len(payload),
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour),
	}

	// Parse HTTP headers
	reader := bufio.NewReader(bytes.NewReader(payload))
	
	// Read first line
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return session, nil // Return partial session
	}

	firstLine = strings.TrimSpace(firstLine)
	parts := strings.Fields(firstLine)

	// Check if it's a request or response
	if len(parts) >= 3 {
		if strings.HasPrefix(parts[0], "HTTP/") {
			// Response
			if code := 0; fmt.Sscanf(parts[1], "%d", &code) == nil {
				session.StatusCode = code
			}
		} else {
			// Request
			session.Method = parts[0]
			session.Path = parts[1]
		}
	}

	// Parse headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			session.Host = strings.TrimSpace(strings.TrimPrefix(line[5:], ""))
		} else if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			session.UserAgent = strings.TrimSpace(strings.TrimPrefix(line[11:], ""))
		}
	}

	return session, nil
}

// ParseICMP parses an ICMP packet
func ParseICMP(pkt *model.Packet) (*model.Session, error) {
	if pkt.Protocol != "ICMP" && pkt.Protocol != "ICMPv6" {
		return nil, ErrNotICMP
	}

	packet := gopacket.NewPacket(pkt.Data, layers.LayerTypeEthernet, gopacket.Default)

	// Get ICMP layer
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		// Try ICMPv6
		icmpLayer = packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			return nil, ErrNotICMP
		}
	}

	session := &model.Session{
		Timestamp: pkt.Timestamp,
		FiveTuple: model.FiveTuple{
			SrcIP:    pkt.SrcIP,
			DstIP:    pkt.DstIP,
			Protocol: "ICMP",
		},
		Type:        "ICMP",
		PayloadSize: pkt.CaptureLen,
		TTL:         pkt.Timestamp.Add(7 * 24 * time.Hour),
	}

	// Extract ICMP details
	if icmp4, ok := icmpLayer.(*layers.ICMPv4); ok {
		session.ICMPType = uint8(icmp4.TypeCode.Type())
		session.ICMPCode = uint8(icmp4.TypeCode.Code())
		session.ICMPSeq = icmp4.Seq
	} else if icmp6, ok := icmpLayer.(*layers.ICMPv6); ok {
		session.ICMPType = uint8(icmp6.TypeCode.Type())
		session.ICMPCode = uint8(icmp6.TypeCode.Code())
	}

	return session, nil
}

// isHTTPData checks if data looks like HTTP
func isHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for HTTP methods or response
	httpPrefixes := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
		[]byte("HTTP/1."),
	}

	for _, prefix := range httpPrefixes {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}

	return false
}

// GetFiveTuple extracts the 5-tuple from a packet
func GetFiveTuple(pkt *model.Packet) model.FiveTuple {
	return model.FiveTuple{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}
}

