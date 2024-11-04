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
	apiReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.apiKey)) // IAM токен
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

	var ocrResponse models.OCRResponse
	err = json.Unmarshal([]byte(body), &ocrResponse)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	iocs, err := h.usecase.GetTextOCRResponse(ocrResponse)

	switch apiResp.StatusCode {
	case http.StatusOK:
		var apiResponse map[string]interface{}
		if err := json.Unmarshal(body, &apiResponse); err != nil {
			common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
			logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
			common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
			logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
			return
		}
		logger.Info("Successfully processed file OCR", slog.String("filename", filename))

	case http.StatusBadRequest:
		common.RespondWithError(w, http.StatusBadRequest, BadRequestMsg)
		logger.Error(BadRequestMsg)
		return

	case http.StatusUnauthorized:
		common.RespondWithError(w, http.StatusUnauthorized, UnauthorizedMsg)
		logger.Error(UnauthorizedMsg)
		return

	case http.StatusRequestEntityTooLarge:
		common.RespondWithError(w, http.StatusRequestEntityTooLarge, ScanFilePayloadTooLargeMsg)
		logger.Error(ScanFilePayloadTooLargeMsg)
		return

	default:
		common.RespondWithError(w, http.StatusInternalServerError, KasperskyUnexpectedError)
		logger.Error(KasperskyUnexpectedError, slog.Int("status_code", apiResp.StatusCode))
		return
	}
}
