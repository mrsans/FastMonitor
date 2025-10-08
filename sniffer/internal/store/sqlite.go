package store

import (
	"database/sql"
	"fmt"
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
	-- DNS sessions table
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
		INDEX idx_dns_timestamp (timestamp),
		INDEX idx_dns_ttl (ttl),
		INDEX idx_dns_domain (domain)
	);

	-- HTTP sessions table
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
		payload_size INTEGER,
		ttl DATETIME NOT NULL,
		INDEX idx_http_timestamp (timestamp),
		INDEX idx_http_ttl (ttl),
		INDEX idx_http_host (host)
	);

	-- ICMP sessions table
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
		INDEX idx_icmp_timestamp (timestamp),
		INDEX idx_icmp_ttl (ttl)
	);
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
				domain, query_type, response_ip, payload_size, ttl
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		model.TableHTTP: `
			INSERT INTO http_sessions (
				timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
				method, host, path, status_code, user_agent, payload_size, ttl
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		model.TableICMP: `
			INSERT INTO icmp_sessions (
				timestamp, src_ip, dst_ip, protocol,
				icmp_type, icmp_code, icmp_seq, payload_size, ttl
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			session.PayloadSize,
			session.TTL,
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
		)
		return err

	default:
		return fmt.Errorf("unknown table type: %s", table)
	}
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

