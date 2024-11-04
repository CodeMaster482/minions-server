package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

var (
	ErrCacheMiss       = errors.New("cache miss")
	ErrRowNotFound     = errors.New("row not found in db")
	ErrUnsupportedFlow = errors.New("")
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

// возвращает слова из запроса OCR без побелов
func (uc *Usecase) GetTextOCRResponse(OCR models.OCRResponse) ([]string, error) {
	var texts []string
	for _, block := range OCR.Result.TextAnnotation.Blocks {
		for _, line := range block.Lines {
			for _, alternative := range line.Alternatives {
				texts = append(texts, strings.TrimSpace(alternative.Text))
				for _, word := range alternative.Words {
					texts = append(texts, strings.TrimSpace(word.Text))
				}
			}
		}
	}

	words := filterWords(texts)

	if len(words) == 0 {
		return nil, errors.New("Not found IOC for screenshot")
	}

	return filterWords(texts)
}

func (uc *Usecase) RequestKasperskyAPI(ctx context.Context, ioc string) (map[string]interface{}, error) {
	var apiPath string

	apiPath, err := getIocFlow(ioc)
	if err != nil {
		return nil, fmt.Errorf("getIocFlow: %w", err)
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com%s?request=%s", apiPath, url.QueryEscape(ioc))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil,
			common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToCreateRequest, slog.Any("error", err))

		return nil, nil
	}

	req.Header.Set("x-api-key", h.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {

		return
	}
	defer resp.Body.Close()
}

func getIocFlow(inputType string) (string, error) {
	switch inputType {
	case "ip":
		apiPath = "/api/v1/search/ip"
	case "url":
		apiPath = "/api/v1/search/url"
	case "domain":
		apiPath = "/api/v1/search/domain"
	default:
		return "", ErrUnsupportedFlow
	}

	return apiPath, nil
}

var apiPath string

func filterWords(words []string) []string {
	urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	ipRegex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	domainRegex := regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)

	var result []string
	for _, word := range words {
		// Проверяем, соответствует ли слово одному из шаблонов
		if urlRegex.MatchString(word) || ipRegex.MatchString(word) || domainRegex.MatchString(word) {
			result = append(result, word)
		}
	}
	return result
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
