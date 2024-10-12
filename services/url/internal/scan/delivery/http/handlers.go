package http

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// Handler содержит зависимости для обработки запросов
type Handler struct {
	apiKey string
	logger *slog.Logger
}

// New создаёт новый экземпляр Handler
func New(apiKey string, logger *slog.Logger) *Handler {
	return &Handler{
		apiKey: apiKey,
		logger: logger,
	}
}

// Url обрабатывает запросы на проверку URL через API Kaspersky
func (h *Handler) Url(w http.ResponseWriter, r *http.Request) {
	// Создаем контекст для логгера с информацией о запросе
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	// Извлекаем веб-адрес из параметра запроса
	webAddress := r.URL.Query().Get("request")
	if webAddress == "" {
		http.Error(w, "Missing 'request' query parameter", http.StatusBadRequest)
		logger.Error("Missing 'request' query parameter")
		return
	}

	// Формируем URL для запроса к API Kaspersky
	apiURL := fmt.Sprintf("https://opentip.kaspersky.com/api/v1/search/url?request=%s", url.QueryEscape(webAddress))

	// Создаём новый HTTP-запрос с контекстом
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		logger.Error("Failed to create request", slog.Any("error", err))
		return
	}

	// Устанавливаем заголовок с API-ключом
	req.Header.Set("x-api-key", h.apiKey)

	// Отправляем запрос к API Kaspersky
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request to Kaspersky API", http.StatusInternalServerError)
		logger.Error("Failed to send request to Kaspersky API", slog.Any("error", err))
		return
	}
	defer resp.Body.Close()

	// Проверяем статус код ответа
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Kaspersky API returned error", http.StatusInternalServerError)
		logger.Error("Kaspersky API returned error", slog.Int("status_code", resp.StatusCode))
		return
	}

	// Устанавливаем заголовок Content-Type
	w.Header().Set("Content-Type", "application/json")

	// Копируем тело ответа API Kaspersky в ответ клиенту
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, "Failed to read response from Kaspersky API", http.StatusInternalServerError)
		logger.Error("Failed to read response from Kaspersky API", slog.Any("error", err))
		return
	}

	logger.Info("Successfully processed request", slog.String("web_address", webAddress))
}
