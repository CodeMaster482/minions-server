package usecase

import (
	"context"
	"errors"
	"fmt"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrCacheMiss   = errors.New("cache miss")
	ErrRowNotFound = errors.New("row not found in db")
)

type Usecase struct {
	postgresRepo scan.Postgres
	redisRepo    scan.Redis
	logger       *slog.Logger
}

func New(postgres scan.Postgres, redis scan.Redis, logger *slog.Logger) *Usecase {
	return &Usecase{
		postgresRepo: postgres,
		redisRepo:    redis,
		logger:       logger,
	}
}

// DetermineInputType определяет тип входной строки: IP, URL или домен.
func (uc *Usecase) DetermineInputType(input string) (string, error) {
	// Удаляем возможные пробелы по краям строки
	input = strings.TrimSpace(input)

	// Проверяем, является ли входная строка IP-адресом
	if net.ParseIP(input) != nil {
		return "ip", nil
	}

	// Проверяем, является ли входная строка URL
	u, err := url.Parse(input)
	if err == nil && u.Scheme != "" && u.Host != "" {
		// Проверяем, есть ли путь, отличный от пустого или "/"
		if u.Path != "" && u.Path != "/" {
			return "url", nil
		}
		// Если путь пустой или "/", считаем это доменом
		return "domain", nil
	}

	// Проверяем, является ли входная строка доменным именем
	if isValidDomain(input) {
		return "domain", nil
	}

	return "", errors.New("invalid input")
}

// isValidDomain проверяет, является ли строка валидным доменным именем.
func isValidDomain(domain string) bool {
	// Регулярное выражение для проверки доменного имени
	var domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$`)
	return domainRegexp.MatchString(domain)
}

func (uc *Usecase) CachedResponse(ctx context.Context, inputType, requestParam string) (string, error) {
	uc.logger.Debug("Attempting to retrieve cached response",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	cachedResponse, err := uc.redisRepo.GetCachedResponse(ctx, inputType, requestParam)
	if err != nil {
		uc.logger.Error("Error retrieving cached response",
			slog.Any("error", err),
		)

		return "", errors.Join(ErrCacheMiss, fmt.Errorf("failed to get cached response: %w", err))
	}

	if cachedResponse == "" {
		uc.logger.Info("Cache miss: no cached response found")

		return "", ErrCacheMiss
	}

	uc.logger.Info("Cache hit: cached response found")

	return cachedResponse, nil
}

func (uc *Usecase) SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error {
	uc.logger.Error("Attempting to set cached response in Redis",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	err := uc.redisRepo.SetCachedResponse(ctx, savedResponse, inputType, requestParam)
	if err != nil {
		uc.logger.Error("Failed to set cached response in Redis",
			slog.Any("error", err),
		)

		return err
	}

	uc.logger.Info("Successfully set cached response in Redis")

	return nil
}

func (uc *Usecase) SavedResponse(ctx context.Context, inputType, requestParam string) (string, error) {
	uc.logger.Debug("Attempting to retrieve saved response",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	savedResponse, err := uc.postgresRepo.GetSavedResponse(ctx, inputType, requestParam)
	if err != nil {
		uc.logger.Error("Error retrieving saved response",
			slog.Any("error", err),
		)

		return "", errors.Join(ErrRowNotFound, fmt.Errorf("failed to get saved response: %w", err))
	}

	if savedResponse == "" {
		uc.logger.Info("No saved response found")

		return "", ErrRowNotFound
	}

	uc.logger.Info("Saved response found")

	return savedResponse, nil
}
