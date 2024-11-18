package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/usecase"
	"github.com/alexedwards/scs/v2"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
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

	// Сообщения об ошибках для DomainIPUrl
	BadRequestMsg          = "Bad Request: Incorrect query."
	UnauthorizedMsg        = "Unauthorized: Authentication failed."
	ForbiddenMsg           = "Forbidden: Quota or request limit exceeded."
	NotFoundMsg            = "Not Found: Lookup results not found."
	InternalServerErrorMsg = "Internal Server Error"

	// Сообщения об ошибках для ScanFile
	ScanFileBadRequestMsg          = "Bad Request: Failed to process the uploaded file."
	ScanFilePayloadTooLargeMsg     = "Payload Too Large: File size exceeds the 256 MB limit."
	ScanFileInternalServerErrorMsg = "Internal Server Error: Unable to process the file."
)

// Size constants
const (
	MB            = 1 << 20
	MaxUploadSize = 256 * MB // Максимальный размер файла 256MB
)

type Handler struct {
	iamToken       string
	apiKey         string
	folderID       string
	usecase        scan.Usecase
	sessionManager *scs.SessionManager
	logger         *slog.Logger
}

func New(apiKey string, iamToken string, folderID string, uc scan.Usecase, sessionManager *scs.SessionManager, logger *slog.Logger) *Handler {
	return &Handler{
		iamToken:       iamToken,
		folderID:       folderID,
		apiKey:         apiKey,
		usecase:        uc,
		sessionManager: sessionManager,
		logger:         logger,
	}
}

// DomainIPUrl
// @Summary Проверка веб-адреса, IP или домена через Kaspersky API
// @Description Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.
// В зависимости от типа входных данных (IPv4, URL или домен), возвращаются соответствующие поля в ответе.
// @ID domain-check
// @Tags Scan
// @Accept json
// @Produce json
// @Param request query string true "Веб-адрес, IP или домен для проверки" example(www.example.com)
// @Success 200 {object} models.ResponseFromAPI "Успешная проверка. Возвращается объединенный ответ с информацией."
// @Failure 400 {object} common.ErrorResponse "Bad Request: Incorrect query."
// @Failure 404 {object} common.ErrorResponse "Not Found: Lookup results not found."
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
//
//	@Example 200 Success {
//	  "Zone": "Green",
//	  "Categories": ["CATEGORY_INFORMATION_TECHNOLOGIES", "CATEGORY_SEARCH_ENGINES_AND_SERVICES"],
//	  "CategoriesWithZone": [
//	    {
//	      "Name": "CATEGORY_INFORMATION_TECHNOLOGIES",
//	      "Zone": "Grey"
//	    },
//	    {
//	      "Name": "CATEGORY_SEARCH_ENGINES_AND_SERVICES",
//	      "Zone": "Grey"
//	    }
//	  ],
//	  "DomainGeneralInfo": {
//	    "FilesCount": 1000,
//	    "UrlsCount": 100000,
//	    "HitsCount": 1000000,
//	    "Domain": "ya.ru",
//	    "Ipv4Count": 205,
//	    "Categories": ["CATEGORY_INFORMATION_TECHNOLOGIES", "CATEGORY_SEARCH_ENGINES_AND_SERVICES"],
//	    "CategoriesWithZone": [
//	      {
//	        "Name": "CATEGORY_INFORMATION_TECHNOLOGIES",
//	        "Zone": "Grey"
//	      },
//	      {
//	        "Name": "CATEGORY_SEARCH_ENGINES_AND_SERVICES",
//	        "Zone": "Grey"
//	      }
//	    ]
//	  },
//	  "DomainWhoIsInfo": {
//	    "DomainName": "ya.ru",
//	    "Created": "1999-07-11T20:00:00Z",
//	    "Updated": "2021-01-01T00:00:00Z",
//	    "Expires": "2025-07-30T21:00:00Z",
//	    "NameServers": ["ns1.yandex.ru", "ns2.yandex.ru"],
//	    "Contacts": [
//	      {
//	        "ContactType": "registrant",
//	        "Organization": "YANDEX, LLC."
//	      }
//	    ],
//	    "Registrar": {
//	      "Info": "RU-CENTER-RU",
//	      "IanaId": "1234"
//	    },
//	    "DomainStatus": ["REGISTERED, DELEGATED, VERIFIED"],
//	    "RegistrationOrganization": "RU-CENTER-RU"
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

	requestParam := r.URL.Query().Get("request")
	if requestParam == "" {
		common.RespondWithError(w, http.StatusBadRequest, BadRequestMsg)
		logger.Error(MissingRequestParam)
		return
	}

	logger.Info("Request from user", requestParam)

	inputType, err := h.usecase.DetermineInputType(requestParam)
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, InvalidInput)
		logger.Error(InvalidInput, slog.Any("error", err))
		return
	}

	// Получаем userID из сессии, если пользователь авторизован
	userID, ok := h.sessionManager.Get(ctx, "user_id").(int)
	if !ok {
		userID = 0 // Или используйте nil, если поддерживается
	}

	// Проверяем наличие в Redis
	var response models.ResponseFromAPI
	cachedResponse, err := h.usecase.CachedResponse(ctx, inputType, requestParam)
	if err == nil {
		// Если найдено в Redis, возвращаем кэшированный ответ
		if err := json.Unmarshal([]byte(cachedResponse), &response); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
				logger.Error(FailedToEncodeResponse, slog.Any("error", err))

				return
			}

			// Обновляем счётчики
			_, err = h.usecase.SavedResponse(ctx, inputType, requestParam)
			if err != nil {
				logger.Warn("Can't update count in PostgreSQL", slog.Any("error", err))
			}

			// Обновляем пользовательский счётчик, если пользователь авторизован
			if userID != 0 {
				err = h.usecase.SaveUserStats(ctx, response.Zone, inputType, requestParam, userID)
				if err != nil {
					logger.Warn("Can't update user stats in PostgreSQL", slog.Any("error", err))
				}
			}

			logger.Info("Returning cached response from Redis", slog.String("request", requestParam))
			return
		}
		// Если произошла ошибка при разборе кэша, продолжаем обработку
	}

	// Ищем в PostgreSQL
	savedResponse, err := h.usecase.SavedResponse(ctx, inputType, requestParam)
	if err == nil {
		if len(savedResponse) != 0 {
			// Если найдено в PostgreSQL, обновляем Redis и возвращаем ответ
			if err := json.Unmarshal([]byte(savedResponse), &response); err == nil {
				err := h.usecase.SetCachedResponse(ctx, savedResponse, inputType, requestParam)
				if err != nil {
					logger.Warn("Cache is not updated in Redis", slog.Any("error", err))
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				err = json.NewEncoder(w).Encode(response)
				if err != nil {
					common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
					logger.Error(FailedToEncodeResponse, slog.Any("error", err))

					return
				}

				// Обновляем счётчики
				_, err = h.usecase.SavedResponse(ctx, inputType, requestParam)
				if err != nil {
					logger.Warn("Can't update count in PostgreSQL", slog.Any("error", err))
				}

				// Обновляем пользовательский счётчик, если пользователь авторизован
				if userID != 0 {
					err = h.usecase.SaveUserStats(ctx, response.Zone, inputType, requestParam, userID)
					if err != nil {
						logger.Warn("Can't update user stats in PostgreSQL", slog.Any("error", err))
					}
				}

				logger.Info("Response from DB was successfully found", slog.String("request", requestParam))
				return
			}
		} else {
			logger.Warn("Got empty saved response")
		}
	} else if !errors.Is(err, usecase.ErrRowNotFound) {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error("No records found in PostgreSQL", slog.Any("error", err))
		return
	}

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

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com%s?request=%s", apiPath, url.QueryEscape(requestParam))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToCreateRequest, slog.Any("error", err))

		return
	}

	req.Header.Set("x-api-key", h.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error(FailedToSendRequest, slog.Any("error", err))

		return
	}
	defer resp.Body.Close()

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

	respJson, err := json.Marshal(apiResponse)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
		logger.Error(FailedToEncodeResponse, slog.Any("error", err))

		return
	}

	w.Write(respJson)

	err = h.usecase.SaveResponse(ctx, string(respJson), apiResponse.Zone, inputType, requestParam, userID)
	if err != nil {
		logger.Warn("Error saving response", slog.Any("error", err))

		return
	}

	err = h.usecase.SetCachedResponse(ctx, string(respJson), inputType, requestParam)
	if err != nil {
		logger.Warn("Cache is not updated in Redis", slog.Any("error", err))
	}

	logger.Info("Successfully processed request", slog.String("request_param", requestParam), slog.String("zone", apiResponse.Zone))
}

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

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com/api/v1/scan/file?filename=%s", url.QueryEscape(filename))

	apiReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(fileContent))
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, ScanFileInternalServerErrorMsg)
		logger.Error(ScanFileInternalServerErrorMsg, slog.Any("error", err))
		return
	}

	apiReq.Header.Set("x-api-key", h.apiKey)
	apiReq.Header.Set("Content-Type", "application/octet-stream")

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

	switch apiResp.StatusCode {
	case http.StatusOK:
		var apiResponse models.FileScanResponse
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
		logger.Info("Successfully processed file scan", slog.String("filename", filename))

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
