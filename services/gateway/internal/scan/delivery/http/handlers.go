package http

import (
	"encoding/json"
	"fmt"
	"github.com/CodeMaster482/minions-server/common"
	"io"
	"net/http"
	"net/url"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
	"log/slog"
)

const (
	MissingRequestParam      = "Missing 'request' query parameter"
	InvalidInput             = "Invalid input"
	UnsupportedInputType     = "Unsupported input type"
	FailedToCreateRequest    = "Failed to create request"
	FailedToSendRequest      = "Failed to send request to Kaspersky API"
	FailedToReadResponse     = "Failed to read response from Kaspersky API"
	FailedToParseResponse    = "Failed to parse response from Kaspersky API"
	FailedToEncodeResponse   = "Failed to encode response"
	KasperskyUnexpectedError = "Kaspersky API returned unexpected error"

	// Ответы клиенту
	BadRequestMsg          = "Bad Request: Incorrect query."
	UnauthorizedMsg        = "Unauthorized: Authentication failed."
	ForbiddenMsg           = "Forbidden: Quota or request limit exceeded."
	NotFoundMsg            = "Not Found: Lookup results not found."
	InternalServerErrorMsg = "Internal Server Error"
)

type Handler struct {
	apiKey  string
	usecase scan.Usecase
	logger  *slog.Logger
}

func New(apiKey string, uc scan.Usecase, logger *slog.Logger) *Handler {
	return &Handler{
		apiKey:  apiKey,
		usecase: uc,
		logger:  logger,
	}
}

// @Summary Проверка веб-адреса, IP или домена через Kaspersky API
// @Description Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.
// В зависимости от типа входных данных (IP, URL или домен), возвращаются соответствующие поля в ответе.
// @ID domain-check
// @Tags Scan
// @Accept json
// @Produce json
// @Param request query string true "Веб-адрес, IP или домен для проверки" example(www.example.com)
// @Success 200 {object} models.ResponseFromAPI "Успешная проверка. Возвращается объединенный ответ с информацией."
// @Failure 400 {object} models.ErrorResponse "Bad Request: Incorrect query."
// @Failure 404 {object} models.ErrorResponse "Not Found: Lookup results not found."
// @Failure 500 {object} models.ErrorResponse "Internal Server Error"
//
//	@Example 200 Success {
//	  "zone": "Red",
//	  "categories": ["Phishing URL"],
//	  "categoriesWithZone": [
//	    {
//	      "name": "Phishing URL",
//	      "zone": "Red"
//	    }
//	  ],
//	  "url_general_info": {
//	    "url": "http://malicious.example.com",
//	    "host": "malicious.example.com",
//	    "ipv4_count": 1,
//	    "files_count": 2,
//	    "categories": ["Phishing URL"],
//	    "categoriesWithZone": [
//	      {
//	        "name": "Phishing URL",
//	        "zone": "Red"
//	      }
//	    ]
//	  },
//	  "url_domain_whois": {
//	    "domain_name": "malicious.example.com",
//	    "created": "2020-01-01T00:00:00Z",
//	    "updated": "2021-01-01T00:00:00Z",
//	    "expires": "2023-01-01T00:00:00Z",
//	    "name_servers": ["ns1.example.com", "ns2.example.com"],
//	    "contacts": ["admin@example.com"],
//	    "registrar": {
//	      "info": "Example Registrar Inc.",
//	      "iana_id": "1234"
//	    },
//	    "domain_status": ["active"],
//	    "registration_organization": "Example Corp"
//	  }
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "Invalid input"
//	}
//
//	@Example 404 Not Found {
//	  "Message": "Not Found: Lookup results not found."
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Internal Server Error"
//	}
//
// @Router /api/scan/uri [get]
func (h *Handler) DomainIPUrl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	// Извлекаем входные данные из параметра запроса
	input := r.URL.Query().Get("request")
	if input == "" {
		common.RespondWithError(w, http.StatusBadRequest, BadRequestMsg)
		logger.Error(MissingRequestParam)
		return
	}

	// Определяем тип входных данных
	inputType, err := h.usecase.DetermineInputType(input)
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, InvalidInput)
		logger.Error(InvalidInput, slog.Any("error", err))
		return
	}

	// Выбираем соответствующий путь API на основе типа входных данных
	var apiPath string
	switch inputType {
	case "ip":
		apiPath = "/api/v1/search/ip"
	case "url":
		apiPath = "/api/v1/search/url"
	case "domain":
		apiPath = "/api/v1/search/domain"
	default:
		common.RespondWithError(w, http.StatusBadRequest, UnsupportedInputType)
		logger.Error(UnsupportedInputType, slog.String("inputType", inputType))
		return
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com%s?request=%s", apiPath, url.QueryEscape(input))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToCreateRequest, slog.Any("error", err))
		return
	}

	// Устанавливаем заголовок с API-ключом
	req.Header.Set("x-api-key", h.apiKey)

	// Отправляем запрос к API
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToSendRequest, slog.Any("error", err))
		return
	}
	defer resp.Body.Close()

	// Обрабатываем различные статусы ответа
	switch resp.StatusCode {
	case http.StatusOK:
		// Всё прошло хорошо, парсим ответ
	case http.StatusBadRequest:
		common.RespondWithError(w, http.StatusBadRequest, BadRequestMsg)
		logger.Error(BadRequestMsg)
		return
	case http.StatusUnauthorized:
		common.RespondWithError(w, http.StatusUnauthorized, UnauthorizedMsg)
		logger.Error(UnauthorizedMsg)
		return
	case http.StatusForbidden:
		common.RespondWithError(w, http.StatusForbidden, ForbiddenMsg)
		logger.Error(ForbiddenMsg)
		return
	case http.StatusNotFound:
		common.RespondWithError(w, http.StatusNotFound, NotFoundMsg)
		logger.Error(NotFoundMsg)
		return
	default:
		common.RespondWithError(w, http.StatusInternalServerError, KasperskyUnexpectedError)
		logger.Error(KasperskyUnexpectedError, slog.Int("status_code", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToReadResponse, slog.Any("error", err))
		return
	}

	var apiResponse models.ResponseFromAPI
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToParseResponse, slog.Any("error", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
		logger.Error(FailedToEncodeResponse, slog.Any("error", err))
		return
	}

	logger.Info("Successfully processed request", slog.String("input", input), slog.String("zone", apiResponse.Zone))
}
