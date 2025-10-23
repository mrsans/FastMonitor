package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/scheduler"
	"sniffer/internal/server"
	"sniffer/internal/store"
)

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
	server.NewApp(cfg, cap, sched, st, dashboard)

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

	// Create Wails application
	r := gin.Default()
	r.Static("/", "./frontend/dist")
	r.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
