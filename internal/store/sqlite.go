package store

import (
	"database/sql"
	"fmt"
	"io"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"sniffer/pkg/model"
)

// SQLiteStore stores parsed sessions in SQLite database
// SQLite数据库存储（派生会话数据）
type SQLiteStore struct {
	mu          sync.RWMutex
	db          *sql.DB
	dbPath      string
	vacuumDays  int
	insertStmts map[model.TableType]*sql.Stmt
}

// GetRawDB returns the underlying *sql.DB
func (s *SQLiteStore) GetRawDB() *sql.DB {
	return s.db
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string, vacuumDays int) (*SQLiteStore, error) {
	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{
		db:          db,
		dbPath:      dbPath,
		vacuumDays:  vacuumDays,
		insertStmts: make(map[model.TableType]*sql.Stmt),
	}

	// Initialize schema
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	// Run migrations
	if err := store.MigrateSchema(); err != nil {
		fmt.Printf("Warning: migration failed: %v\n", err)
		// Don't fail if migration fails, table might already be up-to-date
	}

	// Prepare insert statements
	if err := store.prepareStatements(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

// initSchema creates tables if they don't exist
func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dns_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		protocol TEXT,
		domain TEXT,
		query_type TEXT,
		response_ip TEXT,
		payload_size INTEGER,
		ttl DATETIME NOT NULL,
		process_pid INTEGER,
		process_name TEXT,
		process_exe TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_sessions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_dns_ttl ON dns_sessions(ttl);
	CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_sessions(domain);

	CREATE TABLE IF NOT EXISTS http_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		protocol TEXT,
		method TEXT,
		host TEXT,
		path TEXT,
		status_code INTEGER,
		user_agent TEXT,
		content_type TEXT,
		post_data TEXT,
		payload_size INTEGER,
		ttl DATETIME NOT NULL,
		process_pid INTEGER,
		process_name TEXT,
		process_exe TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_sessions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_http_ttl ON http_sessions(ttl);
	CREATE INDEX IF NOT EXISTS idx_http_host ON http_sessions(host);

	CREATE TABLE IF NOT EXISTS icmp_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		protocol TEXT,
		icmp_type INTEGER,
		icmp_code INTEGER,
		icmp_seq INTEGER,
		payload_size INTEGER,
		ttl DATETIME NOT NULL,
		process_pid INTEGER,
		process_name TEXT,
		process_exe TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_icmp_timestamp ON icmp_sessions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_icmp_ttl ON icmp_sessions(ttl);

	-- 通用会话流表（所有五元组连接的统计）
	CREATE TABLE IF NOT EXISTS session_flows (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		protocol TEXT NOT NULL,
		packet_count INTEGER DEFAULT 1,
		bytes_count INTEGER DEFAULT 0,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		session_type TEXT,
		process_pid INTEGER,
		process_name TEXT,
		process_exe TEXT,
		UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
	);

	CREATE INDEX IF NOT EXISTS idx_flows_first_seen ON session_flows(first_seen);
	CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON session_flows(last_seen);
	CREATE INDEX IF NOT EXISTS idx_flows_protocol ON session_flows(protocol);
	CREATE INDEX IF NOT EXISTS idx_flows_process ON session_flows(process_name);

	-- 告警规则表
	CREATE TABLE IF NOT EXISTS alert_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		rule_type TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		condition_field TEXT NOT NULL,
		condition_operator TEXT NOT NULL,
		condition_value TEXT NOT NULL,
		alert_level TEXT DEFAULT 'warning',
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_alert_rules_type ON alert_rules(rule_type);

	-- 告警记录表
	CREATE TABLE IF NOT EXISTS alert_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER NOT NULL,
		rule_name TEXT NOT NULL,
		rule_type TEXT NOT NULL,
		alert_level TEXT NOT NULL,
		triggered_at DATETIME NOT NULL,
		src_ip TEXT,
		dst_ip TEXT,
		protocol TEXT,
		domain TEXT,
		url TEXT,
		details TEXT,
		acknowledged INTEGER DEFAULT 0,
		acknowledged_at DATETIME,
		acknowledged_by TEXT,
		FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
	);

	CREATE INDEX IF NOT EXISTS idx_alert_logs_triggered_at ON alert_logs(triggered_at);
	CREATE INDEX IF NOT EXISTS idx_alert_logs_rule_id ON alert_logs(rule_id);
	CREATE INDEX IF NOT EXISTS idx_alert_logs_acknowledged ON alert_logs(acknowledged);
	CREATE INDEX IF NOT EXISTS idx_alert_logs_level ON alert_logs(alert_level);
	`

	_, err := s.db.Exec(schema)
	return err
}

// prepareStatements prepares INSERT statements for each table
func (s *SQLiteStore) prepareStatements() error {
	stmts := map[model.TableType]string{
		model.TableDNS: `
			INSERT INTO dns_sessions (
				timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
				domain, query_type, response_ip, payload_size, ttl,
				process_pid, process_name, process_exe
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		model.TableHTTP: `
			INSERT INTO http_sessions (
				timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
				method, host, path, status_code, user_agent, content_type, post_data, payload_size, ttl,
				process_pid, process_name, process_exe
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		model.TableICMP: `
			INSERT INTO icmp_sessions (
				timestamp, src_ip, dst_ip, protocol,
				icmp_type, icmp_code, icmp_seq, payload_size, ttl,
				process_pid, process_name, process_exe
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
	}

	for table, query := range stmts {
		stmt, err := s.db.Prepare(query)
		if err != nil {
			return fmt.Errorf("prepare statement for %s: %w", table, err)
		}
		s.insertStmts[table] = stmt
	}

	return nil
}

// WriteSession writes a session to the appropriate table
func (s *SQLiteStore) WriteSession(table model.TableType, session *model.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stmt, ok := s.insertStmts[table]
	if !ok {
		return fmt.Errorf("no insert statement for table %s", table)
	}

	switch table {
	case model.TableDNS:
		_, err := stmt.Exec(
			session.Timestamp,
			session.FiveTuple.SrcIP,
			session.FiveTuple.DstIP,
			session.FiveTuple.SrcPort,
			session.FiveTuple.DstPort,
			session.FiveTuple.Protocol,
			session.Domain,
			session.QueryType,
			session.ResponseIP,
			session.PayloadSize,
			session.TTL,
			session.ProcessPID,
			session.ProcessName,
			session.ProcessExe,
		)
		return err

	case model.TableHTTP:
		_, err := stmt.Exec(
			session.Timestamp,
			session.FiveTuple.SrcIP,
			session.FiveTuple.DstIP,
			session.FiveTuple.SrcPort,
			session.FiveTuple.DstPort,
			session.FiveTuple.Protocol,
			session.Method,
			session.Host,
			session.Path,
			session.StatusCode,
			session.UserAgent,
			session.ContentType,
			session.PostData,
			session.PayloadSize,
			session.TTL,
			session.ProcessPID,
			session.ProcessName,
			session.ProcessExe,
		)
		return err

	case model.TableICMP:
		_, err := stmt.Exec(
			session.Timestamp,
			session.FiveTuple.SrcIP,
			session.FiveTuple.DstIP,
			session.FiveTuple.Protocol,
			session.ICMPType,
			session.ICMPCode,
			session.ICMPSeq,
			session.PayloadSize,
			session.TTL,
			session.ProcessPID,
			session.ProcessName,
			session.ProcessExe,
		)
		return err

	default:
		return fmt.Errorf("unknown table type: %s", table)
	}
}

// identifySessionType 智能识别会话类型
func identifySessionType(protocol string, srcPort, dstPort uint16) string {
	// 1. 先判断协议层
	if protocol == "ICMP" || protocol == "ICMPv6" {
		return "ICMP"
	}
	
	// 2. 基于知名端口判断应用层协议
	// 检查双向端口（服务端口可能是源或目标）
	ports := []uint16{srcPort, dstPort}
	for _, port := range ports {
		switch port {
		// DNS
		case 53:
			return "DNS"
		
		// HTTP
		case 80, 8080, 8000, 8888:
			return "HTTP"
		
		// HTTPS
		case 443, 8443:
			return "HTTPS"
		
		// FTP
		case 20, 21:
			return "FTP"
		
		// SSH
		case 22:
			return "SSH"
		
		// Telnet
		case 23:
			return "Telnet"
		
		// SMTP
		case 25, 587:
			return "SMTP"
		
		// POP3
		case 110, 995:
			return "POP3"
		
		// IMAP
		case 143, 993:
			return "IMAP"
		
		// SNMP
		case 161, 162:
			return "SNMP"
		
		// LDAP
		case 389, 636:
			return "LDAP"
		
		// RDP
		case 3389:
			return "RDP"
		
		// MySQL
		case 3306:
			return "MySQL"
		
		// PostgreSQL
		case 5432:
			return "PostgreSQL"
		
		// Redis
		case 6379:
			return "Redis"
		
		// MongoDB
		case 27017:
			return "MongoDB"
		}
	}
	
	// 3. 如果没有匹配知名端口，返回协议类型
	if protocol == "TCP" {
		return "TCP"
	} else if protocol == "UDP" {
		return "UDP"
	}
	
	// 4. 其他情况
	return "Other"
}

// UpsertSessionFlow 插入或更新会话流统计（使用UPSERT）
func (s *SQLiteStore) UpsertSessionFlow(pkt *model.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 规范化五元组方向（较小的IP:端口作为源）
	srcIP, dstIP := pkt.SrcIP, pkt.DstIP
	srcPort, dstPort := pkt.SrcPort, pkt.DstPort
	
	// 对于TCP/UDP，规范化方向
	if pkt.Protocol == "TCP" || pkt.Protocol == "UDP" {
		key1 := fmt.Sprintf("%s:%d", srcIP, srcPort)
		key2 := fmt.Sprintf("%s:%d", dstIP, dstPort)
		if key1 > key2 {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
		}
	} else if pkt.Protocol == "ICMP" || pkt.Protocol == "ICMPv6" {
		// ICMP没有端口，只比较IP
		if srcIP > dstIP {
			srcIP, dstIP = dstIP, srcIP
		}
		srcPort, dstPort = 0, 0
	}

	// 智能判断会话类型（基于协议和端口）
	sessionType := identifySessionType(pkt.Protocol, srcPort, dstPort)

	// UPSERT: 如果存在则更新，否则插入
	query := `
		INSERT INTO session_flows (
			src_ip, dst_ip, src_port, dst_port, protocol,
			packet_count, bytes_count, first_seen, last_seen, session_type,
			process_pid, process_name, process_exe
		) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol) DO UPDATE SET
			packet_count = packet_count + 1,
			bytes_count = bytes_count + ?,
			last_seen = ?,
			process_pid = COALESCE(excluded.process_pid, process_pid),
			process_name = COALESCE(NULLIF(excluded.process_name, ''), process_name),
			process_exe = COALESCE(NULLIF(excluded.process_exe, ''), process_exe)
	`

	_, err := s.db.Exec(query,
		// INSERT values
		srcIP, dstIP, srcPort, dstPort, pkt.Protocol,
		pkt.Length, pkt.Timestamp, pkt.Timestamp, sessionType,
		pkt.ProcessPID, pkt.ProcessName, pkt.ProcessExe,
		// UPDATE values
		pkt.Length, pkt.Timestamp,
	)

	return err
}

// LoadSnapshot loads recent sessions from a table
func (s *SQLiteStore) LoadSnapshot(table model.TableType, limit int) ([]*model.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tableName := string(table) + "_sessions"
	query := fmt.Sprintf("SELECT * FROM %s ORDER BY timestamp DESC LIMIT ?", tableName)

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", tableName, err)
	}
	defer rows.Close()

	sessions := make([]*model.Session, 0, limit)

	for rows.Next() {
		session := &model.Session{Type: string(table)}

		switch table {
		case model.TableDNS:
			err = rows.Scan(
				&session.ID,
				&session.Timestamp,
				&session.FiveTuple.SrcIP,
				&session.FiveTuple.DstIP,
				&session.FiveTuple.SrcPort,
				&session.FiveTuple.DstPort,
				&session.FiveTuple.Protocol,
				&session.Domain,
				&session.QueryType,
				&session.ResponseIP,
				&session.PayloadSize,
				&session.TTL,
			)

		case model.TableHTTP:
			err = rows.Scan(
				&session.ID,
				&session.Timestamp,
				&session.FiveTuple.SrcIP,
				&session.FiveTuple.DstIP,
				&session.FiveTuple.SrcPort,
				&session.FiveTuple.DstPort,
				&session.FiveTuple.Protocol,
				&session.Method,
				&session.Host,
				&session.Path,
				&session.StatusCode,
				&session.UserAgent,
				&session.ContentType,
				&session.PostData,
				&session.PayloadSize,
				&session.TTL,
			)

		case model.TableICMP:
			err = rows.Scan(
				&session.ID,
				&session.Timestamp,
				&session.FiveTuple.SrcIP,
				&session.FiveTuple.DstIP,
				&session.FiveTuple.Protocol,
				&session.ICMPType,
				&session.ICMPCode,
				&session.ICMPSeq,
				&session.PayloadSize,
				&session.TTL,
			)
		}

		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		sessions = append(sessions, session)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return sessions, nil
}

// Vacuum removes old sessions before the specified time
func (s *SQLiteStore) Vacuum(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tables := []string{"dns_sessions", "http_sessions", "icmp_sessions"}
	
	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE ttl < ?", table)
		result, err := s.db.Exec(query, before)
		if err != nil {
			return fmt.Errorf("vacuum %s: %w", table, err)
		}

		rows, _ := result.RowsAffected()
		if rows > 0 {
			fmt.Printf("Vacuum: removed %d rows from %s\n", rows, table)
		}
	}

	// Run SQLite VACUUM to reclaim space
	_, err := s.db.Exec("VACUUM")
	if err != nil {
		return fmt.Errorf("sqlite vacuum: %w", err)
	}

	return nil
}

// Stats returns storage statistics
func (s *SQLiteStore) Stats() (StoreStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := StoreStats{}

	// Count rows in each table
	tables := map[model.TableType]string{
		model.TableDNS:  "dns_sessions",
		model.TableHTTP: "http_sessions",
		model.TableICMP: "icmp_sessions",
	}

	for tableType, tableName := range tables {
		var count int64
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
		if err := s.db.QueryRow(query).Scan(&count); err != nil {
			return stats, fmt.Errorf("count %s: %w", tableName, err)
		}

		switch tableType {
		case model.TableDNS:
			stats.DNSCount = count
		case model.TableHTTP:
			stats.HTTPCount = count
		case model.TableICMP:
			stats.ICMPCount = count
		}
	}

	// Get database file size
	var pageCount, pageSize int64
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pageCount); err == nil {
		if err := s.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err == nil {
			stats.TotalSize = pageCount * pageSize
		}
	}

	return stats, nil
}

// ClearAll clears all session data from the database
func (s *SQLiteStore) ClearAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 清空所有数据表
	tables := []string{
		"dns_sessions", 
		"http_sessions", 
		"icmp_sessions", 
		"session_flows",
		"alert_logs", // 清空告警记录(但保留规则)
	}
	
	for _, table := range tables {
		_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// VACUUM to reclaim space
	_, err := s.db.Exec("VACUUM")
	if err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}

	return nil
}

// Close closes the database
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close prepared statements
	for _, stmt := range s.insertStmts {
		stmt.Close()
	}

	return s.db.Close()
}

// ExportPCAP is not implemented for SQLite store
func (s *SQLiteStore) ExportPCAP(start, end time.Time, w io.Writer) error {
	return fmt.Errorf("PCAP export not supported for session store")
}

