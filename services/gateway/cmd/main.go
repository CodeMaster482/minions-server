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

	"database/sql"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	httpSwagger "github.com/swaggo/http-swagger"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/CodeMaster482/minions-server/common"
	_ "github.com/CodeMaster482/minions-server/docs"
	scanHandlers "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/delivery/http"
	scanPostgresRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/repo/postgres"
	scanRedisRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/repo/redis"
	scanUsecase "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/usecase"
	"github.com/CodeMaster482/minions-server/services/gateway/pkg/middleware"
	_ "github.com/lib/pq"
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
	configPath := flag.String("c", "services/gateway/cmd/config.yaml", "Путь к файлу конфигурации")
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

	if cfg.Gateway.LogFile != "" {
		lumberjackLogger := &lumberjack.Logger{
			Filename:   cfg.Gateway.LogFile,
			MaxSize:    100,
			MaxBackups: 0,
			MaxAge:     14,
			Compress:   true,
		}
		writers = append(writers, lumberjackLogger)
	}

	multiWriter := io.MultiWriter(writers...)

	if cfg.Gateway.LogFormat == "json" {
		logger = slog.New(slog.NewJSONHandler(multiWriter, handlerOptions))
	} else {
		logger = slog.New(slog.NewTextHandler(multiWriter, handlerOptions))
	}

	logger.Info("Starting gateway service")

	//=================================================================//

	postgresClient, err := initPostgres(cfg.Postgres)
	if err != nil {
		slog.Error("init Postgres failed", slog.Any("error", err))

		return err
	}
	defer postgresClient.Close()

	//=================================================================//

	redisClient, err := initRedis(cfg.Redis)
	if err != nil {
		slog.Error("init Redis failed", slog.Any("error", err))

		return err
	}
	defer redisClient.Close()

	//=================================================================//

	scanPostgresRepo := scanPostgresRepo.New(postgresClient, logger)
	scanRedisRepo := scanRedisRepo.New(redisClient, logger)
	scanUsecase := scanUsecase.New(scanPostgresRepo, scanRedisRepo, logger)
	scan := scanHandlers.New(cfg.Gateway.KasperskyAPIKey, cfg.Gateway.IamToken, cfg.Gateway.FolderID, scanUsecase, logger)

	//=================================================================//

	r := mux.NewRouter().PathPrefix("/api").Subrouter()

	r.Use(
		middleware.Recovery(logger),
		middleware.Cors,
		middleware.Logging(logger),
	)

	r.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	r.HandleFunc("/scan/uri", scan.DomainIPUrl).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/scan/file", scan.ScanFile).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/screen", scan.ScanScreen).Methods(http.MethodPost, http.MethodOptions)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		common.RespondWithError(w, http.StatusNotFound, "Not Found")
		logger.Warn("Not Found", slog.String("url", r.URL.String()))
	})

	//=================================================================//

	srv := &http.Server{
		Handler:           r,
		Addr:              cfg.Gateway.Address,
		ReadTimeout:       cfg.Gateway.Timeout,
		WriteTimeout:      cfg.Gateway.Timeout,
		IdleTimeout:       cfg.Gateway.IdleTimeout,
		ReadHeaderTimeout: cfg.Gateway.ReadHeaderTimeout,
	}

	// Канал для перехвата сигналов завершения работы
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("ListenAndServe error", slog.Any("error", err))
		}
	}()

	logger.Info("Server started", slog.String("address", cfg.Gateway.Address))

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

func initPostgres(cfg PostgresConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func initRedis(cfg RedisConfig) (*redis.Client, error) {
	options := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	client := redis.NewClient(options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, err
	}

	return client, nil
}
