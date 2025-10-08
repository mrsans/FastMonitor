package netio

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
	"sniffer/pkg/model"
)

var (
	ErrNoPermission = errors.New("insufficient permissions to capture packets")
	ErrNpcapMissing = errors.New("Npcap/WinPcap not installed or version too old")
)

// List returns all available network interfaces
func List() ([]model.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find devices: %w", err)
	}

	interfaces := make([]model.Interface, 0, len(devices))
	for _, dev := range devices {
		iface := model.Interface{
			Name:        dev.Name,
			Description: dev.Description,
			Addresses:   make([]string, 0, len(dev.Addresses)),
			IsLoopback:  isLoopback(dev.Name),
			IsPhysical:  isPhysical(dev.Name, dev.Description),
			IsUp:        true, // pcap only returns active interfaces
		}

		for _, addr := range dev.Addresses {
			if addr.IP != nil {
				iface.Addresses = append(iface.Addresses, addr.IP.String())
			}
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// CheckPermission checks if the current user has permission to capture packets
func CheckPermission() error {
	switch runtime.GOOS {
	case "windows":
		// Check if Npcap/WinPcap is installed
		version, err := pcap.Version()
		if err != nil || version == "" {
			return ErrNpcapMissing
		}

		// Try to open any device to test permissions
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return ErrNpcapMissing
		}
		if len(devices) == 0 {
			return errors.New("no network interfaces found")
		}

		// Try opening the first device
		handle, err := pcap.OpenLive(devices[0].Name, 65535, false, pcap.BlockForever)
		if err != nil {
			if strings.Contains(err.Error(), "Administrator") {
				return fmt.Errorf("%w: requires Administrator privileges", ErrNoPermission)
			}
			return fmt.Errorf("open device failed: %w", err)
		}
		handle.Close()
		return nil

	case "linux":
		// Check for CAP_NET_RAW or root
		if os.Geteuid() == 0 {
			return nil
		}

		// Try to check capabilities (simplified check)
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("%w: requires root or CAP_NET_RAW capability", ErrNoPermission)
		}
		if len(devices) == 0 {
			return errors.New("no network interfaces found")
		}

		// Try opening the first device
		handle, err := pcap.OpenLive(devices[0].Name, 65535, false, pcap.BlockForever)
		if err != nil {
			if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "Operation not permitted") {
				return fmt.Errorf("%w: requires root or CAP_NET_RAW capability", ErrNoPermission)
			}
			return fmt.Errorf("open device failed: %w", err)
		}
		handle.Close()
		return nil

	case "darwin":
		// macOS requires root or admin
		if os.Geteuid() != 0 {
			return fmt.Errorf("%w: requires root privileges", ErrNoPermission)
		}
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Handle represents a packet capture handle
type Handle interface {
	ReadPacketData() ([]byte, CaptureInfo, error)
	SetBPFFilter(filter string) error
	Stats() (Stats, error)
	Close()
}

// CaptureInfo contains metadata about a captured packet
type CaptureInfo struct {
	Timestamp      int64 // Unix timestamp in nanoseconds
	CaptureLength  int
	Length         int
	InterfaceIndex int
}

// Stats contains capture statistics
type Stats struct {
	PacketsReceived  int
	PacketsDropped   int
	PacketsIfDropped int
}

// pcapHandle wraps a pcap.Handle
type pcapHandle struct {
	handle *pcap.Handle
}

// Open opens a network interface for packet capture
func Open(name string, snaplen int32, promisc bool, timeout int) (Handle, error) {
	handle, err := pcap.OpenLive(name, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open interface %s: %w", name, err)
	}

	// Set buffer size if possible
	// Note: This is platform-specific and may not work on all systems
	
	return &pcapHandle{handle: handle}, nil
}

func (h *pcapHandle) ReadPacketData() ([]byte, CaptureInfo, error) {
	data, ci, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, CaptureInfo{}, err
	}

	info := CaptureInfo{
		Timestamp:      ci.Timestamp.UnixNano(),
		CaptureLength:  ci.CaptureLength,
		Length:         ci.Length,
		InterfaceIndex: ci.InterfaceIndex,
	}

	return data, info, nil
}

func (h *pcapHandle) SetBPFFilter(filter string) error {
	if filter == "" {
		return nil
	}
	return h.handle.SetBPFFilter(filter)
}

func (h *pcapHandle) Stats() (Stats, error) {
	stats, err := h.handle.Stats()
	if err != nil {
		return Stats{}, err
	}

	return Stats{
		PacketsReceived:  stats.PacketsReceived,
		PacketsDropped:   stats.PacketsDropped,
		PacketsIfDropped: stats.PacketsIfDropped,
	}, nil
}

func (h *pcapHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}

// isLoopback checks if an interface is a loopback interface
func isLoopback(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "loopback") ||
		strings.Contains(name, "lo0") ||
		name == "lo" ||
		strings.HasPrefix(name, "\\device\\npcap_loopback")
}

// isPhysical checks if an interface is a physical interface
func isPhysical(name, desc string) bool {
	name = strings.ToLower(name)
	desc = strings.ToLower(desc)

	// Virtual interface indicators
	virtualKeywords := []string{
		"virtual", "vmware", "vbox", "virtualbox", "hyper-v",
		"docker", "veth", "bridge", "tap", "tun", "loopback",
		"bluetooth", "vpn", "ppp",
	}

	for _, keyword := range virtualKeywords {
		if strings.Contains(name, keyword) || strings.Contains(desc, keyword) {
			return false
		}
	}

	return true
}

// GetVersion returns the pcap library version
func GetVersion() string {
	return pcap.Version()
}

// GetNpcapDownloadURL returns the download URL for Npcap (Windows only)
func GetNpcapDownloadURL() string {
	return "https://npcap.com/#download"
}

