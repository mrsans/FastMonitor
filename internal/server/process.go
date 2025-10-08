package server

import (
	"fmt"
	"sniffer/internal/process"
)

// GetProcessStats 获取进程流量统计（分页）
func (a *App) GetProcessStats(page, pageSize int) (*ProcessStatsResult, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	
	offset := (page - 1) * pageSize
	
	stats, total, err := a.capture.GetProcessStats(offset, pageSize)
	if err != nil {
		return nil, fmt.Errorf("get process stats: %w", err)
	}
	
	return &ProcessStatsResult{
		Data:  stats,
		Total: total,
		Page:  page,
		PageSize: pageSize,
	}, nil
}

// GetTopProcessesByTraffic 获取流量排名前N的进程
func (a *App) GetTopProcessesByTraffic(limit int) ([]process.ProcessStats, error) {
	if limit < 1 || limit > 100 {
		limit = 10
	}
	
	return a.capture.GetTopProcessesByTraffic(limit)
}

// ClearProcessStats 清空进程统计
func (a *App) ClearProcessStats() error {
	return a.capture.ClearProcessStats()
}

// ProcessStatsResult 进程统计结果
type ProcessStatsResult struct {
	Data     []process.ProcessStats `json:"data"`
	Total    int                     `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
}

