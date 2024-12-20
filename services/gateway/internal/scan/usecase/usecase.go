package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"mvdan.cc/xurls"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

var (
	ErrCacheMiss       = errors.New("cache miss")
	ErrRowNotFound     = errors.New("row not found in db")
	ErrUnsavedZone     = errors.New("zone to save is not Red or Green")
	ErrUnsupportedFlow = errors.New("unsupported request flow")

	allowedHosts = map[string]struct{}{
		"bit.ly":      {},
		"tinyurl.com": {},
		"t.co":        {},
		"goo.gl":      {},
		"rebrand.ly":  {},
		"shorturl.at": {},
		"surl.li":     {},
		"clck.ru":     {},
		"goo.su":      {},
	}
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

// DetermineInputType определяет тип входной строки: IP, URL, домен или развернутую ссылку.
func (uc *Usecase) DetermineInputType(input string) (string, string, error) {
	// Удаляем лишние пробелы
	input = strings.TrimSpace(input)

	// Проверяем, не является ли это чистым IP
	if net.ParseIP(input) != nil {
		return "ip", input, nil
	}

	// Проверяем формат IP:PORT (без схемы)
	if parts := strings.Split(input, ":"); len(parts) == 2 {
		hostPart, portPart := parts[0], parts[1]
		if net.ParseIP(hostPart) != nil {
			if _, err := strconv.Atoi(portPart); err == nil {
				// Это IP:PORT - убираем порт
				return "ip", hostPart, nil
			}
		}
	}

	// Пытаемся распарсить как URL
	u, err := url.Parse(input)
	if err == nil && u.Scheme != "" && u.Host != "" {
		// Попытка развернуть ссылку, если это сокращенный URL
		finalURL, err := uc.resolveRedirects(input)
		if err == nil && finalURL != "" {
			// Повторно парсим финальный URL
			uFinal, _ := url.Parse(finalURL)
			if uFinal != nil && uFinal.Host != "" {
				// Удаляем порт
				host := uFinal.Hostname()

				// Сформируем строку без схемы и порта
				pathPart := ""
				if uFinal.Path != "" && uFinal.Path != "/" {
					pathPart = uFinal.Path
				}
				if uFinal.RawQuery != "" {
					pathPart += "?" + uFinal.RawQuery
				}
				if uFinal.Fragment != "" {
					pathPart += "#" + uFinal.Fragment
				}

				finalStr := host + pathPart

				// Определяем тип по развернутому URL
				if net.ParseIP(host) != nil && pathPart == "" {
					return "ip", host, nil
				}
				if isValidDomain(host) && pathPart == "" {
					return "domain", host, nil
				}
				return "url", finalStr, nil
			}
		}

		// Если редирект не дал результата или произошла ошибка — определяем на основе текущего значения
		// Удаляем порт у текущего URL
		host := u.Hostname()

		pathPart := ""
		if u.Path != "" && u.Path != "/" {
			pathPart = u.Path
		}
		if u.RawQuery != "" {
			pathPart += "?" + u.RawQuery
		}
		if u.Fragment != "" {
			pathPart += "#" + u.Fragment
		}

		finalStr := host + pathPart

		// Проверяем IP без пути
		if net.ParseIP(host) != nil && pathPart == "" {
			return "ip", host, nil
		}
		// Проверяем домен без пути
		if isValidDomain(host) && pathPart == "" {
			return "domain", host, nil
		}
		// Иначе URL
		return "url", finalStr, nil
	}

	// Если не URL и не IP, проверяем домен
	if isValidDomain(input) {
		return "domain", input, nil
	}

	return "", "", errors.New("invalid input")
}

// resolveRedirects развертывает сокращенные ссылки, возвращая финальный URL.
func (uc *Usecase) resolveRedirects(inputURL string) (string, error) {
	// Парсим inputURL и проверяем хост
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	if _, ok := allowedHosts[parsedURL.Host]; !ok {

		return inputURL, nil
	}
	uc.logger.Debug("host is recognized short-link service", "host", parsedURL.Host)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	statusCode := 300
	maxCountRedirect := 0
	for ; statusCode > 299 && statusCode < 400 && maxCountRedirect < 4; maxCountRedirect++ {
		req, err := http.NewRequestWithContext(context.TODO(), "GET", inputURL, nil)
		if err != nil {
			return "", err
		}

		// Добавляем User-Agent, похожий на браузерный
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0")

		resp, err := client.Do(req)
		if err != nil {
			uc.logger.Debug("get short link", slog.Any("error", err))
			return inputURL, err
		}
		defer resp.Body.Close()

		if resp.Header.Get("Location") == "" {
			return inputURL, nil
		}

		inputURL = resp.Header.Get("Location")
		statusCode = resp.StatusCode
	}

	return inputURL, nil // Если перенаправлений не было
}

// возвращает слова из запроса OCR без побелов
func (uc *Usecase) GetTextOCRResponse(OCR models.ApiResponse) ([]string, error) {
	rxRelaxed := xurls.Strict
	withoutString := strings.ReplaceAll(OCR.Result.TextAnnotation.FullText, " ", "")
	matches := rxRelaxed.FindAllString(withoutString, -1)

	var urls []string

	// Сохраняем URL
	urls = append(urls, matches...)

	if len(urls) == 0 {
		return nil, errors.New("couldn't find ioc")
	}

	urlsWithoutDub := removeDuplicateStr(urls)
	return urlsWithoutDub, nil
}

func (uc *Usecase) RequestKasperskyAPI(ctx context.Context, ioc string, apiKey string) (*models.ResponseFromAPI, error) {
	apiPath, err := uc.getIocFlow(ioc)
	if err != nil {
		return nil, fmt.Errorf("getIocFlow: %w", err)
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com%s?request=%s", apiPath, url.QueryEscape(ioc))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-api-key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse *models.ResponseFromAPI
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return apiResponse, nil
}

func (uc *Usecase) getIocFlow(inputType string) (string, error) {
	determineInput, _, err := uc.DetermineInputType(inputType)
	if err != nil {
		return "", fmt.Errorf("uc.DetermineInputType: %w", err)
	}

	switch determineInput {
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

func (uc *Usecase) SaveResponse(ctx context.Context, respJson, zone, inputType, requestParam string, userID int) error {
	uc.logger.Debug("Attempting to save response",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	//// не сохраняем серые и неизвестные зоны
	//switch zone {
	//case "Orange", "Yellow":
	//	zone = "Red"
	//case "Green":
	//case "Red":
	//default:
	//	return ErrUnsavedZone
	//}

	err := uc.postgresRepo.SaveResponse(ctx, respJson, inputType, requestParam)
	if err != nil {
		uc.logger.Error("Error saving general response", slog.Any("error", err))
		return err
	}

	if userID != 0 {
		err = uc.SaveUserStats(ctx, zone, inputType, requestParam, userID)
		if err != nil {
			uc.logger.Error("Error saving user-specific response", slog.Any("error", err))
			return err
		}
	}

	return nil
}

func (uc *Usecase) SaveUserStats(ctx context.Context, zone, inputType, requestParam string, userID int) error {
	uc.logger.Debug("Attempting to save user stats",
		slog.String("user_id", fmt.Sprintf("%d", userID)),
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	err := uc.postgresRepo.SaveUserResponse(ctx, userID, zone, inputType, requestParam)
	if err != nil {
		uc.logger.Error("Error saving user stats", slog.Any("error", err))
		return err
	}

	return nil
}
func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
