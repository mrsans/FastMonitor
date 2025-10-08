package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"sniffer/pkg/model"
)

// CreateAlertRule 创建告警规则
func (s *SQLiteStore) CreateAlertRule(rule *model.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO alert_rules (
			name, rule_type, enabled, condition_field, condition_operator, 
			condition_value, alert_level, description, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	now := time.Now()
	result, err := s.db.Exec(query,
		rule.Name, rule.RuleType, enabled, rule.ConditionField,
		rule.ConditionOperator, rule.ConditionValue, rule.AlertLevel,
		rule.Description, now, now,
	)
	if err != nil {
		return fmt.Errorf("create alert rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	rule.ID = id
	rule.CreatedAt = now
	rule.UpdatedAt = now
	return nil
}

// UpdateAlertRule 更新告警规则
func (s *SQLiteStore) UpdateAlertRule(rule *model.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	query := `
		UPDATE alert_rules SET
			name = ?, rule_type = ?, enabled = ?, condition_field = ?,
			condition_operator = ?, condition_value = ?, alert_level = ?,
			description = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.Exec(query,
		rule.Name, rule.RuleType, enabled, rule.ConditionField,
		rule.ConditionOperator, rule.ConditionValue, rule.AlertLevel,
		rule.Description, time.Now(), rule.ID,
	)
	if err != nil {
		return fmt.Errorf("update alert rule: %w", err)
	}

	return nil
}

// DeleteAlertRule 删除告警规则
func (s *SQLiteStore) DeleteAlertRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete alert rule: %w", err)
	}

	return nil
}

// GetAlertRule 获取告警规则
func (s *SQLiteStore) GetAlertRule(id int64) (*model.AlertRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, name, rule_type, enabled, condition_field, condition_operator,
			   condition_value, alert_level, description, created_at, updated_at
		FROM alert_rules
		WHERE id = ?
	`

	rule := &model.AlertRule{}
	var enabled int

	err := s.db.QueryRow(query, id).Scan(
		&rule.ID, &rule.Name, &rule.RuleType, &enabled, &rule.ConditionField,
		&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get alert rule: %w", err)
	}

	rule.Enabled = enabled == 1
	return rule, nil
}

// QueryAlertRules 查询告警规则列表
func (s *SQLiteStore) QueryAlertRules(q model.AlertRuleQuery) ([]*model.AlertRule, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 构建查询条件
	where := []string{}
	args := []interface{}{}

	if q.RuleType != "" {
		where = append(where, "rule_type = ?")
		args = append(args, q.RuleType)
	}

	if q.Enabled != nil {
		enabled := 0
		if *q.Enabled {
			enabled = 1
		}
		where = append(where, "enabled = ?")
		args = append(args, enabled)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// 查询总数
	countQuery := "SELECT COUNT(*) FROM alert_rules " + whereClause
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count alert rules: %w", err)
	}

	// 查询数据
	query := `
		SELECT id, name, rule_type, enabled, condition_field, condition_operator,
			   condition_value, alert_level, description, created_at, updated_at
		FROM alert_rules ` + whereClause + `
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	queryArgs := append(args, limit, q.Offset)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query alert rules: %w", err)
	}
	defer rows.Close()

	rules := []*model.AlertRule{}
	for rows.Next() {
		rule := &model.AlertRule{}
		var enabled int

		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.RuleType, &enabled, &rule.ConditionField,
			&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel,
			&rule.Description, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			continue
		}

		rule.Enabled = enabled == 1
		rules = append(rules, rule)
	}

	return rules, total, nil
}

// CreateAlertLog 创建告警记录（带去重功能）
func (s *SQLiteStore) CreateAlertLog(log *model.AlertLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查是否存在相同的告警（未确认，且核心字段相同）
	// 相同告警定义：同一规则、同一目标（dst_ip或domain）、未确认
	checkQuery := `
		SELECT id, trigger_count
		FROM alert_logs
		WHERE rule_id = ? 
		  AND acknowledged = 0
		  AND (
		    (dst_ip != '' AND dst_ip = ?) OR 
		    (domain != '' AND domain = ?)
		  )
		ORDER BY triggered_at DESC
		LIMIT 1
	`
	
	var existingID int64
	var triggerCount int64
	err := s.db.QueryRow(checkQuery, log.RuleID, log.DstIP, log.Domain).Scan(&existingID, &triggerCount)
	
	if err == nil {
		// 找到相同告警，更新触发次数和最后触发时间
		updateQuery := `
			UPDATE alert_logs 
			SET trigger_count = trigger_count + 1,
			    last_triggered_at = ?
			WHERE id = ?
		`
		_, err = s.db.Exec(updateQuery, log.TriggeredAt, existingID)
		if err != nil {
			return fmt.Errorf("update alert log: %w", err)
		}
		log.ID = existingID
		log.TriggerCount = triggerCount + 1
		return nil
	} else if err != sql.ErrNoRows {
		// 查询错误
		return fmt.Errorf("check existing alert: %w", err)
	}
	
	// 不存在相同告警，创建新记录
	query := `
		INSERT INTO alert_logs (
			rule_id, rule_name, rule_type, alert_level, triggered_at, last_triggered_at,
			src_ip, dst_ip, protocol, domain, url, details, trigger_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
	`

	result, err := s.db.Exec(query,
		log.RuleID, log.RuleName, log.RuleType, log.AlertLevel, log.TriggeredAt, log.TriggeredAt,
		log.SrcIP, log.DstIP, log.Protocol, log.Domain, log.URL, log.Details,
	)
	if err != nil {
		return fmt.Errorf("create alert log: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	log.ID = id
	log.TriggerCount = 1
	log.LastTriggeredAt = log.TriggeredAt
	return nil
}

// AcknowledgeAlert 确认告警
func (s *SQLiteStore) AcknowledgeAlert(id int64, acknowledgedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		UPDATE alert_logs SET
			acknowledged = 1,
			acknowledged_at = ?,
			acknowledged_by = ?
		WHERE id = ?
	`

	_, err := s.db.Exec(query, time.Now(), acknowledgedBy, id)
	if err != nil {
		return fmt.Errorf("acknowledge alert: %w", err)
	}

	return nil
}

// DeleteAlertLog 删除告警记录
func (s *SQLiteStore) DeleteAlertLog(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_logs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete alert log: %w", err)
	}

	return nil
}

// QueryAlertLogs 查询告警记录
func (s *SQLiteStore) QueryAlertLogs(q model.AlertLogQuery) ([]*model.AlertLog, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 构建查询条件
	where := []string{}
	args := []interface{}{}

	if q.RuleID != nil {
		where = append(where, "rule_id = ?")
		args = append(args, *q.RuleID)
	}

	if q.RuleType != "" {
		where = append(where, "rule_type = ?")
		args = append(args, q.RuleType)
	}

	if q.AlertLevel != "" {
		where = append(where, "alert_level = ?")
		args = append(args, q.AlertLevel)
	}

	if q.Acknowledged != nil {
		ack := 0
		if *q.Acknowledged {
			ack = 1
		}
		where = append(where, "acknowledged = ?")
		args = append(args, ack)
	}

	if q.StartTime != nil {
		where = append(where, "triggered_at >= ?")
		args = append(args, q.StartTime)
	}

	if q.EndTime != nil {
		where = append(where, "triggered_at <= ?")
		args = append(args, q.EndTime)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// 查询总数
	countQuery := "SELECT COUNT(*) FROM alert_logs " + whereClause
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count alert logs: %w", err)
	}

	// 排序
	sortBy := q.SortBy
	if sortBy == "" {
		sortBy = "triggered_at"
	}
	sortOrder := strings.ToUpper(q.SortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}

	// 查询数据
	query := `
		SELECT id, rule_id, rule_name, rule_type, alert_level, triggered_at, last_triggered_at, trigger_count,
			   src_ip, dst_ip, protocol, domain, url, details,
			   acknowledged, acknowledged_at, acknowledged_by
		FROM alert_logs ` + whereClause + `
		ORDER BY ` + sortBy + ` ` + sortOrder + `
		LIMIT ? OFFSET ?
	`

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	queryArgs := append(args, limit, q.Offset)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query alert logs: %w", err)
	}
	defer rows.Close()

	logs := []*model.AlertLog{}
	for rows.Next() {
		log := &model.AlertLog{}
		var acknowledged int
		var acknowledgedAt sql.NullTime
		var acknowledgedBy sql.NullString
		var lastTriggeredAt sql.NullTime

		err := rows.Scan(
			&log.ID, &log.RuleID, &log.RuleName, &log.RuleType, &log.AlertLevel,
			&log.TriggeredAt, &lastTriggeredAt, &log.TriggerCount, 
			&log.SrcIP, &log.DstIP, &log.Protocol, &log.Domain,
			&log.URL, &log.Details, &acknowledged, &acknowledgedAt, &acknowledgedBy,
		)
		if err != nil {
			continue
		}

		log.Acknowledged = acknowledged == 1
		if acknowledgedAt.Valid {
			log.AcknowledgedAt = &acknowledgedAt.Time
		}
		if acknowledgedBy.Valid {
			log.AcknowledgedBy = acknowledgedBy.String
		}
		if lastTriggeredAt.Valid {
			log.LastTriggeredAt = lastTriggeredAt.Time
		} else {
			// 如果last_triggered_at为空，使用triggered_at作为fallback
			log.LastTriggeredAt = log.TriggeredAt
		}

		logs = append(logs, log)
	}

	return logs, total, nil
}

// CheckAlertRules 检查数据包是否触发告警规则
func (s *SQLiteStore) CheckAlertRules(pkt *model.Packet, session *model.Session) error {
	s.mu.RLock()
	
	// 查询所有启用的规则
	query := `
		SELECT id, name, rule_type, condition_field, condition_operator,
			   condition_value, alert_level
		FROM alert_rules
		WHERE enabled = 1
	`
	
	rows, err := s.db.Query(query)
	if err != nil {
		s.mu.RUnlock()
		return fmt.Errorf("query alert rules: %w", err)
	}
	defer rows.Close()

	rules := []struct {
		ID                int64
		Name              string
		RuleType          string
		ConditionField    string
		ConditionOperator string
		ConditionValue    string
		AlertLevel        string
	}{}

	for rows.Next() {
		var rule struct {
			ID                int64
			Name              string
			RuleType          string
			ConditionField    string
			ConditionOperator string
			ConditionValue    string
			AlertLevel        string
		}
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.RuleType, &rule.ConditionField,
			&rule.ConditionOperator, &rule.ConditionValue, &rule.AlertLevel); err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	s.mu.RUnlock()

	// 检查每个规则
	for _, rule := range rules {
		if s.matchRule(pkt, session, rule.RuleType, rule.ConditionField,
			rule.ConditionOperator, rule.ConditionValue) {
			
			// 创建告警记录
			log := &model.AlertLog{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				RuleType:    rule.RuleType,
				AlertLevel:  rule.AlertLevel,
				TriggeredAt: time.Now(),
				SrcIP:       pkt.SrcIP,
				DstIP:       pkt.DstIP,
				Protocol:    pkt.Protocol,
			}

			if session != nil {
				log.Domain = session.Domain
				// HTTP的URL由Host和Path组成
				if session.Host != "" {
					log.URL = session.Host + session.Path
				} else {
					log.URL = session.Path
				}
				log.Details = fmt.Sprintf("触发规则: %s, 类型: %s", rule.Name, rule.RuleType)
			} else {
				log.Details = fmt.Sprintf("触发规则: %s, 协议: %s", rule.Name, pkt.Protocol)
			}
			
			// 添加进程信息到详情
			if pkt.ProcessName != "" {
				log.Details += fmt.Sprintf(", 进程: %s (PID: %d)", pkt.ProcessName, pkt.ProcessPID)
			}

			// 异步写入，避免阻塞
			go s.CreateAlertLog(log)
		}
	}

	return nil
}

// ClearAllAlerts 清空所有告警记录
func (s *SQLiteStore) ClearAllAlerts() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM alert_logs")
	if err != nil {
		return fmt.Errorf("clear alert logs: %w", err)
	}

	return nil
}

// matchRule 检查是否匹配规则
func (s *SQLiteStore) matchRule(pkt *model.Packet, session *model.Session,
	ruleType, field, operator, value string) bool {

	var fieldValue string

	// 根据规则类型获取字段值
	switch ruleType {
	case "dst_ip":
		if field == "dst_ip" {
			fieldValue = pkt.DstIP
		}
	case "dns":
		if session != nil && session.Type == "DNS" {
			if field == "domain" {
				fieldValue = session.Domain
			}
		} else {
			return false
		}
	case "http":
			if session != nil && session.Type == "HTTP" {
			if field == "domain" {
				fieldValue = session.Domain
			} else if field == "url" {
				// HTTP的URL由Host和Path组成
				if session.Host != "" {
					fieldValue = session.Host + session.Path
				} else {
					fieldValue = session.Path
				}
			}
		} else {
			return false
		}
	case "icmp":
		if pkt.Protocol == "ICMP" || pkt.Protocol == "ICMPv6" {
			if field == "src_ip" {
				fieldValue = pkt.SrcIP
			} else if field == "dst_ip" {
				fieldValue = pkt.DstIP
			}
		} else {
			return false
		}
	case "process":
		// 进程告警
		if field == "process_name" {
			fieldValue = pkt.ProcessName
		} else if field == "process_exe" {
			fieldValue = pkt.ProcessExe
		} else if field == "process_pid" {
			fieldValue = fmt.Sprintf("%d", pkt.ProcessPID)
		}
		// 如果进程信息为空，不触发告警
		if fieldValue == "" || fieldValue == "0" {
			return false
		}
	default:
		return false
	}

	// 根据操作符比较（忽略大小写）
	switch operator {
	case "equals":
		return strings.EqualFold(fieldValue, value)
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(value))
	case "regex":
		// 正则表达式使用(?i)标志实现忽略大小写
		pattern := value
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		matched, err := regexp.MatchString(pattern, fieldValue)
		return err == nil && matched
	default:
		return false
	}
}

