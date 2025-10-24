package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sniffer/internal/router"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/scheduler"
	"sniffer/internal/server"
	"sniffer/internal/store"
)

// 嵌入web目录下所有文件（包括子目录）
//
//go:embed web
var webFS embed.FS

// 从嵌入的文件系统中提取web子目录作为根目录
func getWebFS() http.FileSystem {
	// 打开嵌入的web目录
	webDir, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("Failed to get web filesystem: %v", err)
	}
	return http.FS(webDir)
}

func main() {
	// 加载配置
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Printf("Warning: failed to load config: %v, using defaults", err)
		cfg = config.Default()
	}

	// 创建存储
	st, err := store.NewComposite(cfg)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// 获取SQLite存储用于dashboard
	sqliteStore := st.GetDB()

	// 创建dashboard管理器
	dashboard := server.NewDashboardManager(sqliteStore.GetRawDB())

	// 创建捕获器
	cap := capture.New(cfg, st)

	// 创建调度器
	sched := scheduler.New(st, cfg)

	// 创建应用
	app := server.NewApp(cfg, cap, sched, st, dashboard)

	// 后台启动调度器
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	// 处理信号
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
	// 创建Gin引擎
	r := gin.Default()
	// 注册路由
	router.RegistRouter(r, app)
	// 提供嵌入的web资源，将/web作为根路径
	webFileSystem := getWebFS()
	r.StaticFS("/web", webFileSystem)
	// 处理Vue History模式的路由刷新404问题
	r.NoRoute(func(c *gin.Context) {
		// 只处理/web前缀的路径
		if strings.HasPrefix(c.Request.URL.Path, "/web") {
			// 尝试从嵌入的文件系统读取index.html
			file, err := webFileSystem.Open("index.html")
			if err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// 获取文件信息
			fileInfo, err := file.Stat()
			if err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}

			// 读取文件内容
			content := make([]byte, fileInfo.Size())
			_, err = file.Read(content)
			if err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}

			c.Data(http.StatusOK, "text/html; charset=utf-8", content)
			return
		}
		// 非/web路径的404保持默认
		c.Status(http.StatusNotFound)
	})

	// 启动服务器
	log.Println("Server starting on :38080")
	if err := r.Run(":38080"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
