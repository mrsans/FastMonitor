package capture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"sniffer/internal/cache"
	"sniffer/internal/config"
	"sniffer/internal/netio"
	"sniffer/internal/parser"
	"sniffer/internal/store"
	"sniffer/pkg/model"
)

var (
	ErrAlreadyRunning = errors.New("capture already running")
	ErrNotRunning     = errors.New("capture not running")
)

// Capture manages packet capture and processing
// 抓包核心模块
type Capture struct {
	mu sync.RWMutex

	cfg    *config.Config
	store  store.Store
	rings  *cache.RingSet

	// Runtime state
	handle        netio.Handle
	interfaceName string
	isRunning     atomic.Bool
	isPaused      atomic.Bool
	ctx           context.Context
	cancel        context.CancelFunc

	// Metrics
	packetsTotal   atomic.Int64
	packetsDropped atomic.Int64
	bytesTotal     atomic.Int64
	lastMetrics    time.Time
	lastPackets    int64
	lastBytes      int64
	metricsC       chan model.Metrics
}

// New creates a new Capture instance
func New(cfg *config.Config, s store.Store) *Capture {
	limits := cfg.GetLimits()
	
	return &Capture{
		cfg:         cfg,
		store:       s,
		rings:       cache.NewRingSet(limits.RawMax, limits.DNSMax, limits.HTTPMax, limits.ICMPMax),
		lastMetrics: time.Now(),
		metricsC:    make(chan model.Metrics, 10),
	}
}

// Start starts packet capture on the specified interface
func (c *Capture) Start(iface string) error {
	if c.isRunning.Load() {
		return ErrAlreadyRunning
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Open interface
	handle, err := netio.Open(iface, int32(c.cfg.SnapshotLen), c.cfg.Promiscuous, int(c.cfg.GetTimeout()))
	if err != nil {
		return fmt.Errorf("open interface: %w", err)
	}

	c.handle = handle
	c.interfaceName = iface
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.isRunning.Store(true)
	c.isPaused.Store(false)

	// Reset metrics
	c.packetsTotal.Store(0)
	c.packetsDropped.Store(0)
	c.bytesTotal.Store(0)
	c.lastMetrics = time.Now()
	c.lastPackets = 0
	c.lastBytes = 0

	// Start capture goroutine
	go c.captureLoop()

	// Start metrics goroutine
	go c.metricsLoop()

	return nil
}

// Stop stops packet capture
func (c *Capture) Stop() error {
	if !c.isRunning.Load() {
		return ErrNotRunning
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.isRunning.Store(false)
	c.isPaused.Store(false)

	if c.cancel != nil {
		c.cancel()
	}

	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}

	return nil
}

// Pause pauses packet capture (drops packets but keeps connection)
func (c *Capture) Pause() {
	c.isPaused.Store(true)
}

// Resume resumes packet capture
func (c *Capture) Resume() {
	c.isPaused.Store(false)
}

// IsRunning returns whether capture is running
func (c *Capture) IsRunning() bool {
	return c.isRunning.Load()
}

// IsPaused returns whether capture is paused
func (c *Capture) IsPaused() bool {
	return c.isPaused.Load()
}

// GetInterfaceName returns the current interface name
func (c *Capture) GetInterfaceName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.interfaceName
}

// StreamMetrics returns a channel for streaming metrics
func (c *Capture) StreamMetrics() <-chan model.Metrics {
	return c.metricsC
}

// Snapshot returns a snapshot of the specified ring buffer
func (c *Capture) Snapshot(table model.TableType) []interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch table {
	case model.TableRaw:
		return c.rings.GetRaw().Snapshot()
	case model.TableDNS:
		return c.rings.GetDNS().Snapshot()
	case model.TableHTTP:
		return c.rings.GetHTTP().Snapshot()
	case model.TableICMP:
		return c.rings.GetICMP().Snapshot()
	default:
		return nil
	}
}

// UpdateLimits updates the ring buffer limits with smooth migration
func (c *Capture) UpdateLimits(limits config.Limits) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rings.ResizeRaw(limits.RawMax)
	c.rings.ResizeDNS(limits.DNSMax)
	c.rings.ResizeHTTP(limits.HTTPMax)
	c.rings.ResizeICMP(limits.ICMPMax)

	c.cfg.UpdateLimits(limits)
}

// captureLoop is the main packet capture loop
func (c *Capture) captureLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Check if paused
		if c.isPaused.Load() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Read packet
		data, ci, err := c.handle.ReadPacketData()
		if err != nil {
			// Check if it's a timeout or actual error
			if errors.Is(err, context.Canceled) {
				return
			}
			// Timeout is normal, continue
			continue
		}

		// Update metrics
		c.packetsTotal.Add(1)
		c.bytesTotal.Add(int64(ci.Length))

		// Parse packet
		timestamp := time.Unix(0, ci.Timestamp)
		pkt, err := parser.ParsePacket(data, timestamp)
		if err != nil {
			continue
		}

		pkt.CaptureLen = ci.CaptureLength
		pkt.Length = ci.Length

		// Store raw packet
		c.rings.GetRaw().Push(pkt)
		
		// Write to persistent storage (non-blocking)
		go func(p *model.Packet) {
			if err := c.store.WriteRaw(p); err != nil {
				// Log error but don't stop capture
				fmt.Printf("Error writing raw packet: %v\n", err)
			}
		}(pkt)

		// Try to parse as DNS
		if dnsSession, err := parser.ParseDNS(pkt); err == nil {
			c.rings.GetDNS().Push(dnsSession)
			go func(s *model.Session) {
				if err := c.store.WriteSession(model.TableDNS, s); err != nil {
					fmt.Printf("Error writing DNS session: %v\n", err)
				}
			}(dnsSession)
		}

		// Try to parse as HTTP
		if httpSession, err := parser.ParseHTTP(pkt); err == nil {
			c.rings.GetHTTP().Push(httpSession)
			go func(s *model.Session) {
				if err := c.store.WriteSession(model.TableHTTP, s); err != nil {
					fmt.Printf("Error writing HTTP session: %v\n", err)
				}
			}(httpSession)
		}

		// Try to parse as ICMP
		if icmpSession, err := parser.ParseICMP(pkt); err == nil {
			c.rings.GetICMP().Push(icmpSession)
			go func(s *model.Session) {
				if err := c.store.WriteSession(model.TableICMP, s); err != nil {
					fmt.Printf("Error writing ICMP session: %v\n", err)
				}
			}(icmpSession)
		}
	}
}

// metricsLoop periodically calculates and sends metrics
func (c *Capture) metricsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			metrics := c.calculateMetrics()
			
			// Non-blocking send
			select {
			case c.metricsC <- metrics:
			default:
				// Channel full, skip this update
			}
		}
	}
}

// calculateMetrics calculates current metrics
func (c *Capture) calculateMetrics() model.Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	elapsed := now.Sub(c.lastMetrics).Seconds()

	currentPackets := c.packetsTotal.Load()
	currentBytes := c.bytesTotal.Load()

	var pps, bps float64
	if elapsed > 0 {
		pps = float64(currentPackets-c.lastPackets) / elapsed
		bps = float64(currentBytes-c.lastBytes) / elapsed
	}

	c.lastMetrics = now
	c.lastPackets = currentPackets
	c.lastBytes = currentBytes

	// Get dropped packets from handle
	var dropped int64
	if c.handle != nil {
		if stats, err := c.handle.Stats(); err == nil {
			dropped = int64(stats.PacketsDropped)
		}
	}

	return model.Metrics{
		Timestamp:      now,
		Interface:      c.interfaceName,
		IsCapturing:    c.isRunning.Load(),
		IsPaused:       c.isPaused.Load(),
		PacketsTotal:   currentPackets,
		PacketsDropped: dropped,
		BytesTotal:     currentBytes,
		PacketsPerSec:  pps,
		BytesPerSec:    bps,
		RawCount:       c.rings.GetRaw().Len(),
		DNSCount:       c.rings.GetDNS().Len(),
		HTTPCount:      c.rings.GetHTTP().Len(),
		ICMPCount:      c.rings.GetICMP().Len(),
	}
}

// GetMetrics returns the current metrics snapshot
func (c *Capture) GetMetrics() model.Metrics {
	return c.calculateMetrics()
}

