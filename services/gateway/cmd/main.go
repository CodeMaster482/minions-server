package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/alexedwards/scs/v2"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"database/sql"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/CodeMaster482/minions-server/common"
	_ "github.com/CodeMaster482/minions-server/docs"

	scanHandlers "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/delivery/http"
	scanPostgresRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/repo/postgres"
	scanRedisRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/repo/redis"
	scanUsecase "github.com/CodeMaster482/minions-server/services/gateway/internal/scan/usecase"

	authHandlers "github.com/CodeMaster482/minions-server/services/gateway/internal/auth/delivery/http"
	authRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/auth/repo"
	authUsecase "github.com/CodeMaster482/minions-server/services/gateway/internal/auth/usecase"

	statisticsHandlers "github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/delivery/http"
	statisticsRepo "github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/repo"
	statisticsUsecase "github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/usecase"

	"github.com/CodeMaster482/minions-server/services/gateway/pkg/middleware"
	"github.com/alexedwards/scs/redisstore"
	"github.com/gomodule/redigo/redis"
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
		Level: slog.LevelDebug,
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

	redisPool := initRedisPool(cfg.Redis)
	defer redisPool.Close()

	//=================================================================//

	sessionManager, err := initSessionManager(cfg.Gateway.SessionConfig, redisPool)
	if err != nil {
		return err
	}

	//=================================================================//

	authRepo := authRepo.New(postgresClient, logger)
	authUsecase := authUsecase.New(authRepo, logger)
	auth := authHandlers.New(authUsecase, sessionManager, logger)

	//=================================================================//

	statisticsRepo := statisticsRepo.New(postgresClient, logger)
	statisticsUsecase := statisticsUsecase.New(statisticsRepo, logger)
	stat := statisticsHandlers.New(statisticsUsecase, logger, sessionManager)

	//=================================================================//

	scanPostgresRepo := scanPostgresRepo.New(postgresClient, logger)
	scanRedisRepo := scanRedisRepo.New(redisPool, logger)
	scanUsecase := scanUsecase.New(scanPostgresRepo, scanRedisRepo, logger)
	scan := scanHandlers.New(cfg.Gateway.KasperskyAPIKey, cfg.Gateway.IamToken, cfg.Gateway.FolderID, scanUsecase, sessionManager, logger)

	//=================================================================//

	r := mux.NewRouter().PathPrefix("/api").Subrouter()

	mw := middleware.New(sessionManager)

	r.Use(
		mw.Recovery(logger),
		mw.Cors,
		mw.Logging(logger),
		sessionManager.LoadAndSave,
	)

	r.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	authRouter := r.PathPrefix("/").Subrouter()
	authRouter.Use(mw.RequireAuthentication)

	authRouterV2 := authRouter.PathPrefix("/v2").Subrouter()
	rV2 := r.PathPrefix("/v2").Subrouter()

	{
		authRouter.HandleFunc("/stat/top-red-links-day", stat.TopRedLinksDayWithPie).Methods(http.MethodGet, http.MethodOptions)
		authRouter.HandleFunc("/stat/top-green-links-day", stat.TopGreenLinksDayWithPie).Methods(http.MethodGet, http.MethodOptions)

		authRouter.HandleFunc("/stat/top-red-links-week", stat.TopRedLinksWeekWithPie).Methods(http.MethodGet, http.MethodOptions)
		authRouter.HandleFunc("/stat/top-green-links-week", stat.TopGreenLinksWeekWithPie).Methods(http.MethodGet, http.MethodOptions)

		authRouter.HandleFunc("/stat/top-red-links-month", stat.TopRedLinksMonthWithPie).Methods(http.MethodGet, http.MethodOptions)
		authRouter.HandleFunc("/stat/top-green-links-month", stat.TopGreenLinksMonthWithPie).Methods(http.MethodGet, http.MethodOptions)

		r.HandleFunc("/stat/top-red-links-all-time", stat.TopRedLinksAllTimeWithPie).Methods(http.MethodGet, http.MethodOptions)
		r.HandleFunc("/stat/top-green-links-all-time", stat.TopGreenLinksAllTimeWithPie).Methods(http.MethodGet, http.MethodOptions)
	}

	{
		authRouterV2.HandleFunc("/stat/top-red-links-day", stat.TopRedLinksDay).Methods(http.MethodGet, http.MethodOptions)
		authRouterV2.HandleFunc("/stat/top-green-links-day", stat.TopGreenLinksDay).Methods(http.MethodGet, http.MethodOptions)

		authRouterV2.HandleFunc("/stat/top-red-links-week", stat.TopRedLinksWeek).Methods(http.MethodGet, http.MethodOptions)
		authRouterV2.HandleFunc("/stat/top-green-links-week", stat.TopGreenLinksWeek).Methods(http.MethodGet, http.MethodOptions)

		authRouterV2.HandleFunc("/stat/top-red-links-month", stat.TopRedLinksMonth).Methods(http.MethodGet, http.MethodOptions)
		authRouterV2.HandleFunc("/stat/top-green-links-month", stat.TopGreenLinksMonth).Methods(http.MethodGet, http.MethodOptions)

		rV2.HandleFunc("/stat/top-red-links-all-time", stat.TopRedLinksAllTime).Methods(http.MethodGet, http.MethodOptions)
		rV2.HandleFunc("/stat/top-green-links-all-time", stat.TopGreenLinksAllTime).Methods(http.MethodGet, http.MethodOptions)
	}

	{
		r.HandleFunc("/auth/login", auth.Login).Methods(http.MethodPost, http.MethodOptions)
		r.HandleFunc("/auth/register", auth.Register).Methods(http.MethodPost, http.MethodOptions)
		authRouter.HandleFunc("/auth/logout", auth.Logout).Methods(http.MethodPost, http.MethodOptions)
	}

	{
		r.HandleFunc("/scan/uri", scan.DomainIPUrl).Methods(http.MethodGet, http.MethodOptions)
		r.HandleFunc("/scan/file", scan.ScanFile).Methods(http.MethodPost, http.MethodOptions)
		r.HandleFunc("/scan/screen", scan.ScanScreen).Methods(http.MethodPost, http.MethodOptions)
	}

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

func initRedisPool(cfg RedisConfig) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     10,                // Максимальное количество idle соединений
		MaxActive:   100,               // Максимальное количество активных соединений
		IdleTimeout: 240 * time.Second, // Таймаут для idle соединений
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", cfg.Addr,
				redis.DialPassword(cfg.Password),
				redis.DialDatabase(cfg.DB))
			if err != nil {
				return nil, err
			}
			return c, err
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}
}

func initSessionManager(cfgSession SessionConfig, redisClient *redis.Pool) (*scs.SessionManager, error) {
	sessionManager := scs.New()
	sessionManager.Store = redisstore.New(redisClient)
	sessionManager.Cookie.Name = "session_id"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.Secure = cfgSession.CookieSecure
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Lifetime = cfgSession.SessionLifetime
	sessionManager.IdleTimeout = cfgSession.SessionIdleTimeout

	return sessionManager, nil
}
