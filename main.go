package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/scheduler"
	"sniffer/internal/server"
	"sniffer/internal/store"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var icon []byte

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

	// Create Wails application
	err = wails.Run(&options.App{
		Title:             "Network Packet Sniffer",
		Width:             1400,
		Height:            900,
		MinWidth:          1200,
		MinHeight:         700,
		MaxWidth:          2560,
		MaxHeight:         1440,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: false,
		BackgroundColour:  &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Menu:             nil,
		Logger:           nil,
		LogLevel:         logger.DEBUG,
		OnStartup:        app.Startup,
		OnDomReady:       nil,
		OnBeforeClose:    nil,
		OnShutdown:       app.Shutdown,
		WindowStartState: options.Normal,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.SystemDefault,
		},
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  false,
				HideTitleBar:               false,
				FullSizeContent:            false,
				UseToolbar:                 false,
				HideToolbarSeparator:       true,
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
			About: &mac.AboutInfo{
				Title:   "Network Packet Sniffer",
				Message: "A powerful network packet capture and analysis tool built with Wails",
				Icon:    icon,
			},
		},
		Linux: &linux.Options{
			Icon: icon,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

