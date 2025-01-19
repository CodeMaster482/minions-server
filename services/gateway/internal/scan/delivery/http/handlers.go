package http

import (
	"bytes"
	"context"
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
	FailedToEncodeResponse   = "Failed to encode response"
	KasperskyUnexpectedError = "Kaspersky API returned unexpected error"

	BadRequestMsg          = "Bad Request: Incorrect query."
	UnauthorizedMsg        = "Unauthorized: Authentication failed."
	InternalServerErrorMsg = "Internal Server Error"

	ScanFileBadRequestMsg          = "Bad Request: Failed to process the uploaded file."
	ScanFilePayloadTooLargeMsg     = "Payload Too Large: File size exceeds the 256 MB limit."
	ScanFileInternalServerErrorMsg = "Internal Server Error: Unable to process the file."
)

const (
	MB            = 1 << 20
	MaxUploadSize = 256 * MB
)

type Handler struct {
	iamToken       string
	apiKey         string
	vtApiKey       string
	folderID       string
	usecase        scan.Usecase
	sessionManager *scs.SessionManager
	logger         *slog.Logger
}

func New(apiKey string, vtApiKey, iamToken string, folderID string, uc scan.Usecase, sessionManager *scs.SessionManager, logger *slog.Logger) *Handler {
	return &Handler{
		iamToken:       iamToken,
		folderID:       folderID,
		apiKey:         apiKey,
		vtApiKey:       vtApiKey,
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

	logger.Info("Request from user", slog.String("requestParam", requestParam))

	inputType, requestParam, err := h.usecase.DetermineInputType(requestParam)
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, InvalidInput)
		logger.Error(InvalidInput, slog.Any("error", err))
		return
	}

	userID, ok := h.sessionManager.Get(ctx, "user_id").(int)
	if !ok {
		userID = 0
	}
	logger.Info("User ID (unregistered is 0)", slog.Any("userID", userID))

	// Сначала проверяем Redis
	var response models.ResponseFromAPI
	cachedResponse, err := h.usecase.CachedResponse(ctx, inputType, requestParam)
	if err == nil && cachedResponse != "" {
		if err := json.Unmarshal([]byte(cachedResponse), &response); err == nil {
			// Успешно спарсили кэш
			h.returnCachedOrDBResponse(ctx, w, response, inputType, requestParam, userID, logger)
			logger.Info("Returning cached response from Redis", slog.String("request", requestParam))
			return
		}
		// Если ошибка парсинга кэша, идём дальше
	}

	// Проверяем PostgreSQL
	savedResponse, err := h.usecase.SavedResponse(ctx, inputType, requestParam)
	if err == nil && len(savedResponse) != 0 {
		if err := json.Unmarshal([]byte(savedResponse), &response); err == nil {
			// Нашли в БД - обновляем Redis и возвращаем
			if cacheErr := h.usecase.SetCachedResponse(ctx, savedResponse, inputType, requestParam); cacheErr != nil {
				logger.Warn("Cache is not updated in Redis", slog.Any("error", cacheErr))
			}
			h.returnCachedOrDBResponse(ctx, w, response, inputType, requestParam, userID, logger)
			logger.Info("Response from DB was successfully found", slog.String("request", requestParam))
			return
		}
	} else if err != nil && !errors.Is(err, usecase.ErrRowNotFound) {
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		logger.Error("Error reading from PostgreSQL", slog.Any("error", err))
		return
	}

	// Если данные не нашлись ни в Redis, ни в БД, то шлём запросы в обе API
	ctxWithCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	type apiResult struct {
		response models.ResponseFromAPI
		err      error
	}

	resultCh := make(chan apiResult, 2)

	go func() {
		respData, fetchErr := h.fetchKaspersky(ctxWithCancel, inputType, requestParam)
		select {
		case resultCh <- apiResult{response: respData, err: fetchErr}:
		case <-ctxWithCancel.Done():
		}
	}()

	go func() {
		respData, fetchErr := h.fetchVirusTotal(ctxWithCancel, inputType, requestParam)
		select {
		case resultCh <- apiResult{response: respData, err: fetchErr}:
		case <-ctxWithCancel.Done():
		}
	}()

	// Ждём первый успешный ответ
	var finalResult apiResult
	var received int
	for {
		select {
		case <-ctxWithCancel.Done():
			// Если контекст отменён
			if finalResult.err == nil && finalResult.response.Zone == "" {
				finalResult.err = errors.New("context was canceled, no response chosen")
			}
			goto PROCESS_RESULT
		case res := <-resultCh:
			received++
			if res.err == nil {
				finalResult = res
				// отменяем контекст, чтобы прервать вторую горутину
				cancel()
				goto PROCESS_RESULT
			}
			// Если получили ошибку, но это уже второй ответ
			if received == 2 {
				finalResult.err = errors.New("both requests failed")
				goto PROCESS_RESULT
			}
		}
	}

PROCESS_RESULT:
	if finalResult.err != nil {
		logger.Error("Both Kaspersky and VirusTotal failed", slog.Any("error", finalResult.err))
		common.RespondWithError(w, http.StatusInternalServerError, InternalServerErrorMsg)
		return
	}

	response = finalResult.response

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	respJson, err := json.Marshal(response)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
		logger.Error(FailedToEncodeResponse, slog.Any("error", err))
		return
	}
	w.Write(respJson)

	err = h.usecase.SaveResponse(ctx, string(respJson), response.Zone, inputType, requestParam, userID)
	if err != nil {
		logger.Warn("Error saving response", slog.Any("error", err))
	}
	err = h.usecase.SetCachedResponse(ctx, string(respJson), inputType, requestParam)
	if err != nil {
		logger.Warn("Cache is not updated in Redis", slog.Any("error", err))
	}

	logger.Info("Successfully processed request (first response wins)",
		slog.String("request_param", requestParam),
		slog.String("zone", response.Zone))
}

func (h *Handler) returnCachedOrDBResponse(ctx context.Context, w http.ResponseWriter, resp models.ResponseFromAPI,
	inputType, requestParam string, userID int, logger *slog.Logger) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, FailedToEncodeResponse)
		logger.Error(FailedToEncodeResponse, slog.Any("error", err))
		return
	}

	_, err := h.usecase.SavedResponse(ctx, inputType, requestParam)
	if err != nil {
		logger.Warn("Can't update count in PostgreSQL", slog.Any("error", err))
	}

	if userID != 0 {
		err = h.usecase.SaveUserStats(ctx, resp.Zone, inputType, requestParam, userID)
		if err != nil {
			logger.Warn("Can't update user stats in PostgreSQL", slog.Any("error", err))
		}
	}
}

func (h *Handler) fetchKaspersky(ctx context.Context, inputType, requestParam string) (models.ResponseFromAPI, error) {
	var response models.ResponseFromAPI

	var apiPath string
	switch inputType {
	case "ip":
		apiPath = "/api/v1/search/ip"
	case "url":
		apiPath = "/api/v1/search/url"
	case "domain":
		apiPath = "/api/v1/search/domain"
	default:
		return response, errors.New("unsupported input type for Kaspersky")
	}

	apiURL := fmt.Sprintf("https://opentip.kaspersky.com%s?request=%s", apiPath, url.QueryEscape(requestParam))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return response, fmt.Errorf("kaspersky request create failed: %w", err)
	}

	req.Header.Set("x-api-key", h.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return response, fmt.Errorf("kaspersky request send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return response, fmt.Errorf("kaspersky unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return response, fmt.Errorf("kaspersky read body failed: %w", err)
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return response, fmt.Errorf("kaspersky parse json failed: %w", err)
	}

	return response, nil
}

func (h *Handler) fetchVirusTotal(ctx context.Context, inputType, requestParam string) (models.ResponseFromAPI, error) {
	var out models.ResponseFromAPI

	var vtURL string
	switch inputType {
	case "ip":
		vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(requestParam))
	case "domain":
		vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", url.PathEscape(requestParam))
	case "url":
		vtURL = fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", url.PathEscape(requestParam))
	default:
		return out, errors.New("unsupported input type for VirusTotal")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vtURL, nil)
	if err != nil {
		return out, fmt.Errorf("virustotal request create failed: %w", err)
	}

	req.Header.Set("x-apikey", h.vtApiKey)
	req.Header.Set("accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("virustotal request send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("virustotal unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, fmt.Errorf("virustotal read body failed: %w", err)
	}

	var vtResp models.VtData
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return out, fmt.Errorf("virustotal parse json failed: %w", err)
	}

	maliciousCount := vtResp.Data.Attributes.LastAnalysisStats["malicious"]
	suspiciousCount := vtResp.Data.Attributes.LastAnalysisStats["suspicious"]

	var zone string
	switch {
	case maliciousCount > 0:
		zone = "Red"
	case suspiciousCount > 0:
		zone = "Grey"
	default:
		zone = "Green"
	}

	out.Zone = zone

	var categories []string
	for catKey, catVal := range vtResp.Data.Attributes.Categories {
		categories = append(categories, fmt.Sprintf("%s: %s", catKey, catVal))
	}

	for _, tag := range vtResp.Data.Attributes.Tags {
		categories = append(categories, tag)
	}
	out.Categories = categories

	switch inputType {
	case "ip":
		ipAttrib := vtResp.Data.Attributes

		out.IpGeneralInfo = &models.IpGeneralInfo{
			Ip:          requestParam,
			CountryCode: ipAttrib.Country,
			Categories:  categories,
			HitsCount: ipAttrib.LastAnalysisStats["harmless"] +
				ipAttrib.LastAnalysisStats["malicious"] +
				ipAttrib.LastAnalysisStats["suspicious"] +
				ipAttrib.LastAnalysisStats["timeout"] +
				ipAttrib.LastAnalysisStats["undetected"],
			FirstSeen: fmt.Sprintf("%d", ipAttrib.LastModificationDate),
		}

		if ipAttrib.Reputation < 0 {
			out.IpGeneralInfo.Status = "blacklisted"
		} else {
			out.IpGeneralInfo.Status = "known"
		}

		if ipAttrib.Whois != "" {
			asnInfos := []models.AsnInfo{}
			if ipAttrib.Asn > 0 {
				asnInfos = append(asnInfos, models.AsnInfo{
					Number:      ipAttrib.Asn,
					Description: []string{ipAttrib.AsOwner},
				})
			}

			out.IpWhoIs = &models.IpWhoIs{
				Asn: asnInfos,
				Net: &models.NetInfo{
					Name:        ipAttrib.Network,
					Description: ipAttrib.AsOwner,
					Created:     fmt.Sprintf("%d", ipAttrib.WhoisDate),
				},
			}
		}

	case "domain":
		domainAttrib := vtResp.Data.Attributes

		out.DomainGeneralInfo = &models.DomainGeneralInfo{
			Domain:     requestParam,
			FilesCount: domainAttrib.LastAnalysisStats["malicious"] + domainAttrib.LastAnalysisStats["suspicious"],
			UrlsCount: domainAttrib.LastAnalysisStats["harmless"] +
				domainAttrib.LastAnalysisStats["malicious"] +
				domainAttrib.LastAnalysisStats["suspicious"] +
				domainAttrib.LastAnalysisStats["timeout"] +
				domainAttrib.LastAnalysisStats["undetected"],
			HitsCount:  int(domainAttrib.TimesSubmitted),
			Categories: categories,
			Ipv4Count:  0,
		}

		if domainAttrib.Whois != "" {
			out.DomainWhoIsInfo = &models.WhoIsInfo{
				DomainName:               requestParam,
				RegistrationOrganization: domainAttrib.Whois,
				Created:                  fmt.Sprintf("%d", domainAttrib.WhoisDate),
			}
		}

	case "url":
		urlAttrib := vtResp.Data.Attributes

		out.UrlGeneralInfo = &models.UrlGeneralInfo{
			Url: requestParam,
			Host: func() string {
				if urlAttrib.LastFinalURL != "" {
					u, err := url.Parse(urlAttrib.LastFinalURL)
					if err == nil {
						return u.Host
					}
				}
				return ""
			}(),
			FilesCount: urlAttrib.LastAnalysisStats["malicious"] + urlAttrib.LastAnalysisStats["suspicious"],
			Ipv4Count:  int(urlAttrib.TimesSubmitted),
			Categories: categories,
		}

		if urlAttrib.Whois != "" {
			out.UrlDomainWhoIs = &models.WhoIsInfo{
				DomainName:               requestParam,
				RegistrationOrganization: urlAttrib.Whois,
				Created:                  fmt.Sprintf("%d", urlAttrib.WhoisDate),
			}
		}
	}

	return out, nil
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
