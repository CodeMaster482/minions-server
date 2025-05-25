package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

// ScanFile
// @Summary Сканирует файл с использованием API Kaspersky
// @Description Эндпоинт для сканирования файла и получения базового отчета от API Kaspersky.
// @ID file-scan
// @Tags Scan
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "File to scan"
// @Success 200 {object} models.FileScanResponse "Successful scan. Returns basic information about the analyzed file."
// @Failure 400 {object} common.ErrorResponse "Bad Request: Failed to process the uploaded file."
// @Failure 401 {object} common.ErrorResponse "Unauthorized: Authentication failed."
// @Failure 413 {object} common.ErrorResponse "Payload Too Large: File size exceeds the 256 Mb limit."
// @Failure 500 {object} common.ErrorResponse "Internal Server Error: Unable to process the file."
//
//	@Example 200 Success {
//	  "Zone": "Red",
//	  "FileGeneralInfo": {
//	    "FileStatus": "Malware",
//	    "Sha1": "abc123...",
//	    "Md5": "def456...",
//	    "Sha256": "ghi789...",
//	    "FirstSeen": "2022-01-01T00:00:00Z",
//	    "LastSeen": "2022-10-01T00:00:00Z",
//	    "Size": 123456,
//	    "Type": "Executable",
//	    "HitsCount": 100
//	  },
//	  "DetectionsInfo": [
//	    {
//	      "LastDetectDate": "2022-10-01T00:00:00Z",
//	      "DescriptionUrl": "https://threats.kaspersky.com/en/threat/DetectedObject",
//	      "Zone": "Red",
//	      "DetectionName": "Trojan.Win32.Malware",
//	      "DetectionMethod": "Signature"
//	    }
//	  ],
//	  "DynamicDetections": [
//	    {
//	      "Zone": "Red",
//	      "Threat": 1
//	    }
//	  ]
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "Неверный запрос: Не удалось обработать загруженный файл."
//	}
//
//	@Example 401 Unauthorized {
//	  "Message": "Неавторизован: Ошибка аутентификации."
//	}
//
//	@Example 413 Payload Too Large {
//	  "Message": "Слишком большой размер данных: Размер файла превышает 256 МБ."
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Внутренняя ошибка сервера: Не удалось обработать файл."
//	}
//
// @Router /api/scan/file [post]
func (h *Handler) ScanFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)

	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		if err.Error() == "http: request body too large" {
			common.RespondWithError(w, http.StatusRequestEntityTooLarge, models.ScanFilePayloadTooLargeMsg)
			logger.Error(models.ScanFilePayloadTooLargeMsg, slog.Any("error", err))
			return
		}
		common.RespondWithError(w, http.StatusBadRequest, models.ScanFileBadRequestMsg)
		logger.Error(models.ScanFileBadRequestMsg, slog.Any("error", err))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.ScanFileBadRequestMsg)
		logger.Error(models.ScanFileBadRequestMsg, slog.Any("error", err))
		return
	}
	defer file.Close()

	filename := header.Filename
	logger.Info("Received file for scanning", slog.String("filename", filename))

	if header.Size > MaxUploadSize {
		common.RespondWithError(w, http.StatusRequestEntityTooLarge, models.ScanFilePayloadTooLargeMsg)
		logger.Error(models.ScanFilePayloadTooLargeMsg, slog.Int64("file_size", header.Size))
		return
	}

	fileContent, err := io.ReadAll(file)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
		logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com/api/v1/scan/file?filename=%s", url.QueryEscape(filename))

	apiReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(fileContent))
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
		logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	apiReq.Header.Set("x-api-key", h.apiKey)
	apiReq.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	apiResp, err := client.Do(apiReq)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
		logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}
	defer apiResp.Body.Close()

	body, err := io.ReadAll(apiResp.Body)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
		logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	switch apiResp.StatusCode {
	case http.StatusOK:
		var apiResponse models.FileScanResponse
		if err := json.Unmarshal(body, &apiResponse); err != nil {
			common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
			logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(apiResponse); err != nil {
			common.RespondWithError(w, http.StatusInternalServerError, models.ScanFileInternalServerErrorMsg)
			logger.Error(models.ScanFileInternalServerErrorMsg, slog.Any("error", err))
			return
		}
		logger.Info("Successfully processed file scan", slog.String("filename", filename))

	case http.StatusBadRequest:
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		logger.Error(models.BadRequestMsg)
		return

	case http.StatusUnauthorized:
		common.RespondWithError(w, http.StatusUnauthorized, models.UnauthorizedMsg)
		logger.Error(models.UnauthorizedMsg)
		return

	case http.StatusRequestEntityTooLarge:
		common.RespondWithError(w, http.StatusRequestEntityTooLarge, models.ScanFilePayloadTooLargeMsg)
		logger.Error(models.ScanFilePayloadTooLargeMsg)
		return

	default:
		common.RespondWithError(w, http.StatusInternalServerError, models.KasperskyUnexpectedError)
		logger.Error(models.KasperskyUnexpectedError, slog.Int("status_code", apiResp.StatusCode))
		return
	}
}
