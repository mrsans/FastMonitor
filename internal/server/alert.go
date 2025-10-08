package server

import (
	"fmt"

	"sniffer/pkg/model"
)

// CreateAlertRule 创建告警规则
func (a *App) CreateAlertRule(rule model.AlertRule) (*model.AlertRule, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	if err := sqliteStore.CreateAlertRule(&rule); err != nil {
		return nil, err
	}

	return &rule, nil
}

// UpdateAlertRule 更新告警规则
func (a *App) UpdateAlertRule(rule model.AlertRule) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.UpdateAlertRule(&rule)
}

// DeleteAlertRule 删除告警规则
func (a *App) DeleteAlertRule(id int64) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.DeleteAlertRule(id)
}

// GetAlertRule 获取告警规则
func (a *App) GetAlertRule(id int64) (*model.AlertRule, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	return sqliteStore.GetAlertRule(id)
}

// QueryAlertRules 查询告警规则列表
func (a *App) QueryAlertRules(query model.AlertRuleQuery) (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	rules, total, err := sqliteStore.QueryAlertRules(query)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data":  rules,
		"total": total,
	}, nil
}

// QueryAlertLogs 查询告警记录
func (a *App) QueryAlertLogs(query model.AlertLogQuery) (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	logs, total, err := sqliteStore.QueryAlertLogs(query)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data":  logs,
		"total": total,
	}, nil
}

// AcknowledgeAlert 确认告警
func (a *App) AcknowledgeAlert(id int64, acknowledgedBy string) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.AcknowledgeAlert(id, acknowledgedBy)
}

// DeleteAlertLog 删除告警记录
func (a *App) DeleteAlertLog(id int64) error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.DeleteAlertLog(id)
}

// GetAlertStats 获取告警统计
func (a *App) GetAlertStats() (map[string]interface{}, error) {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	db := sqliteStore.GetRawDB()

	// 统计各级别告警数量
	var critical, error, warning, info int64
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'critical' AND acknowledged = 0").Scan(&critical)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'error' AND acknowledged = 0").Scan(&error)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'warning' AND acknowledged = 0").Scan(&warning)
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE alert_level = 'info' AND acknowledged = 0").Scan(&info)

	// 统计启用的规则数
	var enabledRules int64
	db.QueryRow("SELECT COUNT(*) FROM alert_rules WHERE enabled = 1").Scan(&enabledRules)

	// 统计今日告警数
	var todayAlerts int64
	db.QueryRow("SELECT COUNT(*) FROM alert_logs WHERE DATE(triggered_at) = DATE('now')").Scan(&todayAlerts)

	return map[string]interface{}{
		"critical":      critical,
		"error":         error,
		"warning":       warning,
		"info":          info,
		"enabled_rules": enabledRules,
		"today_alerts":  todayAlerts,
		"total_unack":   critical + error + warning + info,
	}, nil
}

// ClearAllAlerts 清空所有告警记录
func (a *App) ClearAllAlerts() error {
	sqliteStore := a.store.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("database not available")
	}

	return sqliteStore.ClearAllAlerts()
}

