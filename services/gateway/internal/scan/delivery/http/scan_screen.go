package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

// DomainIPUrl
// @Summary Проверка веб-адреса, IP или домена через Kaspersky API
// @Description Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.
// В зависимости от типа входных данных (IPv4, URL или домен), возвращаются соответствующие поля в ответе.
// @ID domain-check
// @Tags Scan
// @Accept json
// @Produce json
// @Param request query string true "Веб-адрес, IP или домен для проверки" example(www.example.com)
// @Success 200 {object} map[string]*models.ResponseFromAPI "Успешная проверка. Возвращается объединенный ответ с информацией."
// @Failure 400 {object} common.ErrorResponse "Bad Request: Incorrect query."
// @Failure 404 {object} common.ErrorResponse "Not Found: Lookup results not found."
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
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
func (h *Handler) ScanScreen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)

	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		if err.Error() == "http: request body too large" {
			common.RespondWithError(w, http.StatusRequestEntityTooLarge, ScanFilePayloadTooLargeMsg)
			logger.Error(ScanFilePayloadTooLargeMsg, slog.Any("error", err))
			return
		}
		common.RespondWithError(w, http.StatusBadRequest, ScanFileBadRequestMsg)
		logger.Error(ScanFileBadRequestMsg, slog.Any("error", err))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, ScanFileBadRequestMsg)
		logger.Error(ScanFileBadRequestMsg, slog.Any("error", err))
		return
	}
	defer file.Close()

	filename := header.Filename
	logger.Info("Received file for scanning", slog.String("filename", filename))

	if header.Size > MaxUploadSize {
		common.RespondWithError(w, http.StatusRequestEntityTooLarge, ScanFilePayloadTooLargeMsg)
		logger.Error(ScanFilePayloadTooLargeMsg, slog.Int64("file_size", header.Size))
		return
	}

	fileContent, err := io.ReadAll(file)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	// Закодировать содержимое файла в base64
	base64Content := base64.StdEncoding.EncodeToString(fileContent)

	// Подготовка данных для отправки в Yandex OCR API
	data := map[string]interface{}{
		"mimeType":      "application/octet-stream", // Или измените на mime-type файла
		"languageCodes": []string{"*"},
		"content":       base64Content,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Error preparing OCR request data")
		logger.Error("Error preparing OCR request data", slog.Any("error", err))
		return
	}

	// Подготовка запроса к API
	apiURL := "https://ocr.api.cloud.yandex.net/ocr/v1/recognizeText"
	apiReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(payload))
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	// Установка заголовков
	apiReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.iamToken)) // IAM токен
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("x-folder-id", h.folderID)
	apiReq.Header.Set("x-data-logging-enabled", "true")

	// Выполнение запроса к Yandex API
	client := &http.Client{}
	apiResp, err := client.Do(apiReq)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}
	defer apiResp.Body.Close()

	body, err := io.ReadAll(apiResp.Body)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	var ocrResponse models.ApiResponse
	err = json.Unmarshal([]byte(body), &ocrResponse)
	logger.Debug("Yandex response", slog.Any("res", ocrResponse))

	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	iocs, err := h.usecase.GetTextOCRResponse(ocrResponse)
	if err != nil {
		common.RespondWithError(w, http.StatusNotFound, models.ScanScreenNotFoundIOC)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
	}

	infoIocs := make(map[string]*models.ResponseFromAPI)

	for _, ioc := range iocs {
		res, err := h.usecase.RequestKasperskyAPI(ctx, ioc, h.apiKey)
		if err != nil {
			logger.Warn("Failed to process IOC", slog.Any("ioc", ioc), slog.Any("error", err))
			continue
		}
		infoIocs[ioc] = res
	}

	if len(infoIocs) > 0 {
		RespondWithJSON(w, http.StatusOK, infoIocs)
		logger.Info("Successfully processed IOCs", slog.Int("count", len(infoIocs)))
	} else {
		common.RespondWithError(w, http.StatusNotFound, "No IOCs found")
		logger.Warn("No IOCs were processed successfully")
	}

}

// RespondWithJSON отправляет ответ с данными в формате JSON
func RespondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
