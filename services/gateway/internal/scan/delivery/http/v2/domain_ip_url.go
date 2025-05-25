package v2

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
)

// DomainIPUrl
// @Summary Проверка веб-адреса, IP или домена через Kaspersky API
// @Description Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.
// В зависимости от типа входных данных (IPv4, URL или домен), возвращаются соответствующие поля в ответе.
// @ID universal-check-v2
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
// @Router /api/v2/scan/uri [get]
func (h *Handler) DomainIPUrl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := h.logger.With(
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote", r.RemoteAddr),
	)

	raw := r.URL.Query().Get("request")
	if raw == "" {
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		log.Error("missing request parameter")
		return
	}

	inType, param, err := h.usecase.DetermineInputType(raw)
	if err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.InvalidInput)
		log.Error("determine input type failed", slog.Any("err", err))
		return
	}

	userID, _ := h.sessionManager.Get(ctx, "user_id").(int)

	// 1) Попытаться вернуть из Redis или Postgres
	if h.tryFromCacheOrDB(ctx, w, inType, param, userID, log) {
		return
	}

	// 2) Запросы к Kaspersky и VT параллельно, побеждает первый успешный
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	type res struct {
		models.ResponseFromAPI
		err error
	}
	ch := make(chan res, 2)

	fetchers := []func(context.Context, string, string) (models.ResponseFromAPI, error){
		h.fetchKaspersky, h.fetchVirusTotal,
	}
	for _, fn := range fetchers {
		go func(fetch func(context.Context, string, string) (models.ResponseFromAPI, error)) {
			resp, err := fetch(ctx2, inType, param)
			select {
			case ch <- res{resp, err}:
			case <-ctx2.Done():
			}
		}(fn)
	}

	var final models.ResponseFromAPI
	for i := 0; i < 2; i++ {
		rlt := <-ch
		if rlt.err == nil {
			final = rlt.ResponseFromAPI
			cancel() // прервать вторую горутину
			break
		}
		if i == 1 {
			log.Error("both API calls failed", slog.Any("last_err", rlt.err))
			common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
			return
		}
	}

	// 3) Отдать ответ, сохранить в БД и кэш
	h.writeAndPersist(ctx, w, final, inType, param, userID, log)
}

func (h *Handler) tryFromCacheOrDB(ctx context.Context, w http.ResponseWriter, inType, param string, userID int, log *slog.Logger) bool {
	// Redis
	if data, err := h.usecase.CachedResponse(ctx, inType, param); err == nil && data != "" {
		var resp models.ResponseFromAPI
		if err := json.Unmarshal([]byte(data), &resp); err == nil {
			h.returnJSON(w, resp)
			log.Info("returned from Redis cache", slog.String("param", param))
			h.saveUserStat(ctx, inType, param, resp.Zone, userID, log)
			return true
		}
		log.Warn("failed to unmarshal cache", slog.Any("err", err))
	}
	// Postgres
	if data, err := h.usecase.SavedResponse(ctx, inType, param); err == nil && len(data) > 0 {
		var resp models.ResponseFromAPI
		if err := json.Unmarshal([]byte(data), &resp); err == nil {
			// обновляем Redis
			if err := h.usecase.SetCachedResponse(ctx, data, inType, param); err != nil {
				log.Warn("failed to update Redis cache", slog.Any("err", err))
			}
			h.returnJSON(w, resp)
			log.Info("returned from DB", slog.String("param", param))
			h.saveUserStat(ctx, inType, param, resp.Zone, userID, log)
			return true
		}
		log.Warn("failed to unmarshal DB data", slog.Any("err", err))
	}
	return false
}

func (h *Handler) writeAndPersist(ctx context.Context, w http.ResponseWriter, resp models.ResponseFromAPI, inType, param string, userID int, log *slog.Logger) {
	payload, err := json.Marshal(resp)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.FailedToEncodeResponse)
		log.Error("marshal response failed", slog.Any("err", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)

	if err := h.usecase.SaveResponse(ctx, string(payload), resp.Zone, inType, param, userID); err != nil {
		log.Warn("failed to save response in DB", slog.Any("err", err))
	}
	if err := h.usecase.SetCachedResponse(ctx, string(payload), inType, param); err != nil {
		log.Warn("failed to cache response", slog.Any("err", err))
	}
	h.saveUserStat(ctx, inType, param, resp.Zone, userID, log)
	log.Info("successfully processed", slog.String("param", param), slog.String("zone", resp.Zone))
}

func (h *Handler) saveUserStat(ctx context.Context, inType, param, zone string, userID int, log *slog.Logger) {
	if userID == 0 {
		return
	}
	if err := h.usecase.SaveUserStats(ctx, zone, inType, param, userID); err != nil {
		log.Warn("failed to save user stats", slog.Any("err", err))
	}
}

func (h *Handler) returnJSON(w http.ResponseWriter, resp models.ResponseFromAPI) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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
