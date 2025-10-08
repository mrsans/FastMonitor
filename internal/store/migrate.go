package store

import (
	"fmt"
)

// MigrateSchema 数据库迁移，添加新字段
func (s *SQLiteStore) MigrateSchema() error {
	// 定义所有需要迁移的字段
	migrations := []struct {
		table  string
		column string
		typ    string
	}{
		{"http_sessions", "content_type", "TEXT"},
		{"http_sessions", "post_data", "TEXT"},
		{"dns_sessions", "process_pid", "INTEGER"},
		{"dns_sessions", "process_name", "TEXT"},
		{"dns_sessions", "process_exe", "TEXT"},
		{"http_sessions", "process_pid", "INTEGER"},
		{"http_sessions", "process_name", "TEXT"},
		{"http_sessions", "process_exe", "TEXT"},
		{"icmp_sessions", "process_pid", "INTEGER"},
		{"icmp_sessions", "process_name", "TEXT"},
		{"icmp_sessions", "process_exe", "TEXT"},
		{"alert_logs", "trigger_count", "INTEGER DEFAULT 1"},
		{"alert_logs", "last_triggered_at", "DATETIME"},
	}

	for _, m := range migrations {
		var hasColumn int
		err := s.db.QueryRow(fmt.Sprintf(`
			SELECT COUNT(*) FROM pragma_table_info('%s') 
			WHERE name='%s'
		`, m.table, m.column)).Scan(&hasColumn)
		
		if err != nil {
			return fmt.Errorf("check %s.%s column: %w", m.table, m.column, err)
		}

		if hasColumn == 0 {
			fmt.Printf("Migrating database: adding %s.%s column...\n", m.table, m.column)
			_, err = s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, m.table, m.column, m.typ))
			if err != nil {
				return fmt.Errorf("add %s.%s column: %w", m.table, m.column, err)
			}
		}
	}

	fmt.Println("Database migration completed")
	return nil
}


