package http

import (
	"encoding/json"
	"fmt"
	"github.com/CodeMaster482/minions-server/services/scan/internal/scan/models"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

type Handler struct {
	apiKey string
	logger *slog.Logger
}

func New(apiKey string, logger *slog.Logger) *Handler {
	return &Handler{
		apiKey: apiKey,
		logger: logger,
	}
}

// @Summary Проверка домена через Kaspersky API
// @Description Эндпоинт для проверки домена и определения его цвета на основе зоны риска
// @ID domain-check
// @Tags Domain
// @Accept json
// @Produce json
// @Param request query string true "Домен для проверки"
// @Success 200 {object} models.ResponseToClient "Успешная проверка домена. Возможные значения цвета: Red, Green, Grey."
// @Failure 400 "Некорректный запрос или ошибка в параметрах"
// @Failure 404 "Результаты поиска не найдены"
// @Failure 500 "Внутренняя ошибка сервера"
// @Router /api/scan/domain [get]
func (h *Handler) Domain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	// Извлекаем домен из параметра запроса
	domain := r.URL.Query().Get("request")
	if domain == "" {
		http.Error(w, "Missing 'request' query parameter", http.StatusBadRequest)
		logger.Error("Missing 'request' query parameter")
		return
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com/api/v1/search/domain?request=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		logger.Error("Failed to create request", slog.Any("error", err))
		return
	}

	// Устанавливаем заголовок с API-ключом
	req.Header.Set("x-api-key", h.apiKey)

	// Отправляем запрос к API
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request to Kaspersky API", http.StatusInternalServerError)
		logger.Error("Failed to send request to Kaspersky API", slog.Any("error", err))
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Всё прошло хорошо, парсим ответ
	case http.StatusBadRequest:
		http.Error(w, "Bad Request: Incorrect query.", http.StatusBadRequest)
		logger.Error("Bad Request from Kaspersky API")
		return
	case http.StatusUnauthorized:
		http.Error(w, "Unauthorized: Authentication failed.", http.StatusBadRequest)
		logger.Error("Unauthorized: Authentication failed")
		return
	case http.StatusForbidden:
		http.Error(w, "Forbidden: Quota or request limit exceeded.", http.StatusBadRequest)
		logger.Error("Forbidden: Quota or request limit exceeded")
		return
	case http.StatusNotFound:
		http.Error(w, "Not Found: Lookup results not found.", http.StatusNotFound)
		logger.Error("Not Found: Lookup results not found")
		return
	default:
		http.Error(w, "Kaspersky API returned unexpected error", http.StatusInternalServerError)
		logger.Error("Kaspersky API returned unexpected error", slog.Int("status_code", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response from Kaspersky API", http.StatusInternalServerError)
		logger.Error("Failed to read response from Kaspersky API", slog.Any("error", err))
		return
	}

	var apiResponse models.ResponseFromAPI
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		http.Error(w, "Failed to parse response from Kaspersky API", http.StatusInternalServerError)
		logger.Error("Failed to parse response from Kaspersky API", slog.Any("error", err))
		return
	}

	// Определяем цвет на основе значения Zone
	var color string
	switch apiResponse.Zone {
	case "Red", "Orange", "Yellow":
		color = "Red"
	case "Grey":
		color = "Grey"
	case "Green":
		color = "Green"
	default:
		color = "unknown"
		logger.Warn("Unknown zone value", slog.String("zone", apiResponse.Zone))
	}

	response := models.ResponseToClient{
		Color: color,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		logger.Error("Failed to encode response", slog.Any("error", err))
		return
	}

	logger.Info("Successfully processed request", slog.String("domain", domain), slog.String("color", color))
}
