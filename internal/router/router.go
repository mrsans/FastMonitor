package router

import (
	"github.com/gin-gonic/gin"
	"sniffer/internal/config"
	"sniffer/internal/server"
	"sniffer/pkg/model"
	"strconv"
)

func StrToInt64(value string) int64 {
	i, _ := strconv.ParseInt(value, 10, 64)
	return i
}

func StrToInt(value string) int {
	atoi, _ := strconv.Atoi(value)
	return atoi
}

// regist router
func RegistRouter(r *gin.Engine, app *server.App) {
	apiGroup := r.Group("/api")
	{
		apiGroup.GET("/getInterfaces", func(c *gin.Context) {
			interfaces, _ := app.GetInterfaces()
			c.JSON(200, interfaces)
		})
		apiGroup.GET("/getLimits", func(c *gin.Context) {
			limits := app.GetLimits()
			c.JSON(200, limits)
		})
		apiGroup.GET("/getDashboardStats", func(c *gin.Context) {
			stats, _ := app.GetDashboardStats()
			c.JSON(200, stats)
		})
		apiGroup.GET("/stopCapture", func(c *gin.Context) {
			app.StopCapture()
			c.JSON(200, nil)
		})
		apiGroup.POST("/acknowledgeAlert", func(c *gin.Context) {
			id := StrToInt64(c.PostForm("id"))
			acknowledgedBy := c.PostForm("acknowledgedBy")
			app.AcknowledgeAlert(id, acknowledgedBy)
			c.JSON(200, nil)
		})
		apiGroup.POST("/updateAlertRule", func(c *gin.Context) {
			var rule model.AlertRule
			if err := c.ShouldBindJSON(&rule); err == nil {
				app.UpdateAlertRule(rule)
				c.JSON(200, nil)
			} else {
				c.JSON(500, "create rule fail")
			}
		})
		apiGroup.POST("/updateConfig", func(c *gin.Context) {
			var newCfg *config.Config
			if err := c.ShouldBindJSON(newCfg); err == nil {
				app.UpdateConfig(newCfg)
				c.JSON(200, nil)
			} else {
				c.JSON(500, "create rule fail")
			}
		})
		apiGroup.POST("/updateLimits", func(c *gin.Context) {
			var limits config.Limits
			if err := c.ShouldBindJSON(&limits); err == nil {
				app.UpdateLimits(limits)
				c.JSON(200, nil)
			} else {
				c.JSON(500, "create rule fail")
			}
		})
		apiGroup.GET("/checkPermission", func(c *gin.Context) {
			app.CheckPermission()
			c.JSON(200, nil)
		})
		apiGroup.GET("/vacuumStorage", func(c *gin.Context) {
			app.VacuumStorage()
			c.JSON(200, nil)
		})
		apiGroup.GET("/clearAllAlerts", func(c *gin.Context) {
			app.ClearAllAlerts()
			c.JSON(200, nil)
		})
		apiGroup.GET("/clearAllData", func(c *gin.Context) {
			app.ClearProcessStats()
			c.JSON(200, nil)
		})
		apiGroup.POST("/createAlertRule", func(c *gin.Context) {
			var alertRule model.AlertRule
			if err := c.ShouldBindJSON(&alertRule); err == nil {
				rule, _ := app.CreateAlertRule(alertRule)
				c.JSON(200, rule)
			} else {
				c.JSON(500, "create rule fail")
			}
		})
		apiGroup.POST("/deleteAlertLog", func(c *gin.Context) {
			id := StrToInt64(c.PostForm("id"))
			app.DeleteAlertLog(id)
			c.JSON(200, nil)
		})
		apiGroup.POST("/deleteAlertRule", func(c *gin.Context) {
			id := StrToInt64(c.PostForm("id"))
			app.DeleteAlertRule(id)
			c.JSON(200, nil)
		})
		// TODO 下载文件
		apiGroup.POST("/exportPCAP", func(c *gin.Context) {
			startTime := StrToInt64(c.PostForm("startTime"))
			endTime := StrToInt64(c.PostForm("endTime"))
			app.ExportPCAP(startTime, endTime)
			c.JSON(200, nil)
		})
		apiGroup.GET("/getProcessStats", func(c *gin.Context) {
			page := StrToInt(c.Query("page"))
			size := StrToInt(c.Query("size"))
			stats, _ := app.GetProcessStats(page, size)
			c.JSON(200, stats)
		})
		apiGroup.GET("/getAlertStats", func(c *gin.Context) {
			stats, _ := app.GetAlertStats()
			c.JSON(200, stats)
		})
		apiGroup.GET("/getTopProcessesByTraffic", func(c *gin.Context) {
			limit, _ := strconv.Atoi(c.Query("limit"))
			stats, _ := app.GetTopProcessesByTraffic(limit)
			c.JSON(200, stats)
		})
		apiGroup.GET("/getAlertRule", func(c *gin.Context) {
			id := StrToInt64(c.Query("id"))
			stats, _ := app.GetAlertRule(id)
			c.JSON(200, stats)
		})
		apiGroup.GET("/getConfig", func(c *gin.Context) {
			config := app.GetConfig()
			c.JSON(200, config)
		})
		apiGroup.GET("/getSessions", func(c *gin.Context) {
			table := c.Query("table")
			limit := StrToInt(c.Query("limit"))
			sessions, _ := app.GetSessions(table, limit)
			c.JSON(200, sessions)
		})
		apiGroup.GET("/getSnapshot", func(c *gin.Context) {
			table := c.Query("table")
			limit := StrToInt(c.Query("limit"))
			sessions, _ := app.GetSnapshot(table, limit)
			c.JSON(200, sessions)
		})
		apiGroup.GET("/getProtocolDistribution", func(c *gin.Context) {
			distribution, _ := app.GetProtocolDistribution()
			c.JSON(200, distribution)
		})
		apiGroup.GET("/isCapturing", func(c *gin.Context) {
			capturing := app.IsCapturing()
			c.JSON(200, capturing)
		})
		apiGroup.GET("/getNpcapDownloadURL", func(c *gin.Context) {
			config := app.GetNpcapDownloadURL()
			c.JSON(200, config)
		})
		apiGroup.GET("/pauseCapture", func(c *gin.Context) {
			app.PauseCapture()
			c.JSON(200, nil)
		})
		apiGroup.POST("/querySessionFlows", func(c *gin.Context) {
			var opts model.SessionFlowQuery
			if err := c.ShouldBindJSON(&opts); err == nil {
				flows, _ := app.QuerySessionFlows(opts)
				c.JSON(200, flows)
			} else {
				c.JSON(500, "convert fail")
			}
		})
		apiGroup.GET("/isPaused", func(c *gin.Context) {
			config := app.IsPaused()
			c.JSON(200, config)
		})
		apiGroup.GET("/resumeCapture", func(c *gin.Context) {
			app.ResumeCapture()
			c.JSON(200, nil)
		})
		apiGroup.POST("/querySessions", func(c *gin.Context) {
			var opts model.SessionFlowQuery
			if err := c.ShouldBindJSON(&opts); err == nil {
				flows, _ := app.QuerySessionFlows(opts)
				c.JSON(200, flows)
			} else {
				c.JSON(500, "convert fail")
			}
		})
		apiGroup.GET("/getMetrics", func(c *gin.Context) {
			config := app.GetMetrics()
			c.JSON(200, config)
		})
		apiGroup.GET("/getLibraryVersion", func(c *gin.Context) {
			config := app.GetLibraryVersion()
			c.JSON(200, config)
		})
		apiGroup.GET("/getCurrentInterface", func(c *gin.Context) {
			config := app.GetCurrentInterface()
			c.JSON(200, config)
		})
		apiGroup.POST("/queryAlertLogs", func(c *gin.Context) {
			var query model.AlertLogQuery
			if err := c.ShouldBindJSON(&query); err == nil {
				stats, _ := app.QueryAlertLogs(query)
				c.JSON(200, stats)
			} else {
				c.JSON(200, "alert log convert json fail")
			}
		})
		apiGroup.POST("/queryAlertRules", func(c *gin.Context) {
			var query model.AlertRuleQuery
			if err := c.ShouldBindJSON(&query); err == nil {
				rules, _ := app.QueryAlertRules(query)
				c.JSON(200, rules)
			} else {
				c.JSON(500, "query alert rules convert fail")
			}
		})
		apiGroup.GET("/getStorageStats", func(c *gin.Context) {
			stats, _ := app.GetStorageStats()
			c.JSON(200, stats)
		})
		apiGroup.POST("/startCapture", func(c *gin.Context) {
			iface := c.PostForm("iface")
			app.StartCapture(iface)
			c.JSON(200, nil)
		})
		apiGroup.GET("/getRawPackets", func(c *gin.Context) {
			limit := StrToInt(c.Query("limit"))
			packets, _ := app.GetRawPackets(limit)
			c.JSON(200, packets)
		})
	}

}
