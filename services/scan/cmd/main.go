package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "github.com/CodeMaster482/minions-server/docs"
	scanHandlers "github.com/CodeMaster482/minions-server/services/scan/internal/scan/delivery/http"
)

// @title Minions API
// @description API server for Minions.

// @contact.name Dima
// @contact.url http://t.me/BelozerovD
func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("c", "services/scan/cmd/config.yaml", "Путь к файлу конфигурации")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("config_load_error",
			slog.String("message", fmt.Sprintf("Failed to load config: %v", err)),
			slog.Any("error", err),
		)
		return err
	}

	var handlerOptions = &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	var logger *slog.Logger
	var writers []io.Writer

	writers = append(writers, os.Stdout)

	if cfg.LogFile != "" {
		lumberjackLogger := &lumberjack.Logger{
			Filename:   cfg.LogFile,
			MaxSize:    100,
			MaxBackups: 0,
			MaxAge:     14,
			Compress:   true,
		}
		writers = append(writers, lumberjackLogger)
	}

	multiWriter := io.MultiWriter(writers...)

	if cfg.LogFormat == "json" {
		logger = slog.New(slog.NewJSONHandler(multiWriter, handlerOptions))
	} else {
		logger = slog.New(slog.NewTextHandler(multiWriter, handlerOptions))
	}

	logger.Info("Starting URL service")

	scan := scanHandlers.New(cfg.KasperskyAPIKey, logger)

	r := mux.NewRouter().PathPrefix("/api").Subrouter()

	r.Use(
		recoveryMiddleware(logger),
		corsMiddleware,
		loggingMiddleware(logger),
	)

	r.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	r.HandleFunc("/scan/domain", scan.Domain).Methods(http.MethodGet, http.MethodOptions)

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
		logger.Warn("Not Found", slog.String("url", r.URL.String()))
	})

	srv := &http.Server{
		Handler:           r,
		Addr:              cfg.Address,
		ReadTimeout:       cfg.Timeout,
		WriteTimeout:      cfg.Timeout,
		IdleTimeout:       cfg.IdleTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	// Канал для перехвата сигналов завершения работы
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("ListenAndServe error", slog.Any("error", err))
		}
	}()

	logger.Info("Server started", slog.String("address", cfg.Address))

	// Ожидаем сигнала завершения
	<-quit
	logger.Info("Server is shutting down...")

	// Контекст с таймаутом для корректного завершения работы сервера
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server Shutdown Failed", slog.Any("error", err))
		return err
	}

	logger.Info("Server exited properly")
	return nil
}
