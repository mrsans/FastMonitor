package main

import (
	"context"
	"embed"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sniffer/internal/router"
	"strings"
	"syscall"

	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/scheduler"
	"sniffer/internal/server"
	"sniffer/internal/store"
)

//go:embed frontend/dist/index.html
var Static embed.FS

func main() {
	// Load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Printf("Warning: failed to load config: %v, using defaults", err)
		cfg = config.Default()
	}

	// Create store
	st, err := store.NewComposite(cfg)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Get underlying SQLite store for dashboard
	sqliteStore := st.GetDB()

	// Create dashboard manager
	dashboard := server.NewDashboardManager(sqliteStore.GetRawDB())

	// Create capture
	cap := capture.New(cfg, st)

	// Create scheduler
	sched := scheduler.New(st, cfg)

	// Create app
	app := server.NewApp(cfg, cap, sched, st, dashboard)

	// Start scheduler in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
		if cap.IsRunning() {
			cap.Stop()
		}
		st.Close()
		os.Exit(0)
	}()
	app.Startup(ctx)
	// Create Wails application
	r := gin.Default()
	// regist router
	// r.Static("/", "./frontend/dist")
	router.RegistRouter(r, app)

	r.Static("/web", "./web")

	// 关键步骤 2：解决 Vue 路由刷新 404 问题（如果 Vue 用了 history 模式）
	// 当访问一个不存在的路径时，返回 Vue 的 index.html，让 Vue 自己处理路由
	r.NoRoute(func(c *gin.Context) {
		// 只处理 /web 前缀的路径，避免影响 API 路由
		if strings.HasPrefix(c.Request.URL.Path, "/web") {
			c.File("./web/index.html")
			return
		}
		// 非 /web 路径的 404 保持默认
		c.Status(http.StatusNotFound)
	})

	r.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
