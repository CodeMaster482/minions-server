package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/usecase"
)

// DomainIPUrl
// @Summary Проверка веб-адреса, IP или домена через Kaspersky API
// @Description Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.
// В зависимости от типа входных данных (IPv4, URL или домен), возвращаются соответствующие поля в ответе.
// @ID universal-check
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
func (h *Handler) DomainIPUrlV1(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	requestParam := r.URL.Query().Get("request")
	if requestParam == "" {
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		logger.Error(models.MissingRequestParam)
		return
	}

	logger.Info("Request from user", slog.String("requestParam", requestParam))

	inputType, requestParam, err := h.usecase.DetermineInputType(requestParam)
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.InvalidInput)
		logger.Error(models.InvalidInput, slog.Any("error", err))
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
		common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
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
		common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
		return
	}

	response = finalResult.response

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	respJson, err := json.Marshal(response)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.FailedToEncodeResponse)
		logger.Error(models.FailedToEncodeResponse, slog.Any("error", err))
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
		common.RespondWithError(w, http.StatusInternalServerError, models.FailedToEncodeResponse)
		logger.Error(models.FailedToEncodeResponse, slog.Any("error", err))
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
