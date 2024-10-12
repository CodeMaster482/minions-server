package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	scanHandlers "github.com/CodeMaster482/minions-server/services/url/internal/scan/delivery/http"
	"github.com/gorilla/mux"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		slog.Error("config_load_error",
			slog.String("message", fmt.Sprintf("Failed to load config: %v", err)),
			slog.Any("error", err),
		)
		return err
	}

	handlerOptions := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	var logger *slog.Logger
	if cfg.LogFormat == "json" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, handlerOptions))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, handlerOptions))
	}

	logger.Info("Starting URL service")

	handlerAPI := scanHandlers.New(cfg.KasperskyAPIKey, logger)

	r := mux.NewRouter().PathPrefix("/api").Subrouter()

	r.Use(
		recoveryMiddleware(logger),
		corsMiddleware,
		loggingMiddleware(logger),
	)

	r.HandleFunc("/scan/url", handlerAPI.Url).Methods(http.MethodGet, http.MethodOptions)

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
