package v2

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

// Request structures for each handler
type IPCheckRequest struct {
	IP string `json:"ip" validate:"required,ip"`
}

type URLCheckRequest struct {
	URL string `json:"url" validate:"required,url"`
}

type DomainCheckRequest struct {
	Domain string `json:"domain" validate:"required,fqdn"`
}

// CheckIP
// @Summary Проверка IP-адреса через Kaspersky и VirusTotal API
// @Description Эндпоинт для проверки IP-адреса и получения объединенного ответа с информацией из Kaspersky и VirusTotal API.
// Возвращается информация о репутации IP, географическом местоположении, ASN и WHOIS данных.
// @ID ip-check-v2
// @Tags Scan
// @Accept json
// @Produce json
// @Param request body IPCheckRequest true "IP-адрес для проверки"
// @Success 200 {object} models.ResponseFromAPI "Успешная проверка IP-адреса"
// @Failure 400 {object} common.ErrorResponse "Bad Request: Некорректный запрос или неверный формат IP"
// @Failure 404 {object} common.ErrorResponse "Not Found: Результаты поиска не найдены"
// @Failure 405 {object} common.ErrorResponse "Method Not Allowed: Разрешен только POST метод"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
//
//	@Example 200 Success {
//	  "Zone": "Green",
//	  "Categories": ["benign", "clean"],
//	  "IpGeneralInfo": {
//	    "Ip": "8.8.8.8",
//	    "CountryCode": "US",
//	    "Status": "known",
//	    "FirstSeen": "1577836800",
//	    "HitsCount": 50000,
//	    "Categories": ["dns", "public"]
//	  },
//	  "IpWhoIs": {
//	    "Asn": [
//	      {
//	        "Number": 15169,
//	        "Description": ["Google LLC"]
//	      }
//	    ],
//	    "Net": {
//	      "Name": "8.8.8.0/24",
//	      "Description": "Google LLC",
//	      "Created": "2014-03-14"
//	    }
//	  }
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "IP address is required"
//	}
//
//	@Example 405 Method Not Allowed {
//	  "Message": "Method not allowed"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Internal Server Error"
//	}
//
// @Router /api/v2/scan/ip [post]
func (h *Handler) CheckIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	log := h.logger.With(
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote", r.RemoteAddr),
		slog.String("handler", "CheckIP"),
	)

	var req IPCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		log.Error("failed to decode request body", slog.Any("err", err))
		return
	}

	if req.IP == "" {
		common.RespondWithError(w, http.StatusBadRequest, "IP address is required")
		log.Error("missing IP parameter")
		return
	}

	// Validate IP format
	inType := "ip"
	if _, _, err := h.usecase.DetermineInputType(req.IP); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.InvalidInput)
		log.Error("invalid IP format", slog.Any("err", err))
		return
	}

	userID, _ := h.sessionManager.Get(ctx, "user_id").(int)

	// Try from cache or DB
	if h.tryFromCacheOrDB(ctx, w, inType, req.IP, userID, log) {
		return
	}

	// Fetch from APIs
	final, err := h.fetchFromAPIs(ctx, inType, req.IP, log)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
		return
	}

	// Return response and persist
	h.writeAndPersist(ctx, w, final, inType, req.IP, userID, log)
}

// CheckURL
// @Summary Проверка URL через Kaspersky и VirusTotal API
// @Description Эндпоинт для проверки URL и получения объединенного ответа с информацией из Kaspersky и VirusTotal API.
// Возвращается информация о безопасности URL, категориях, хосте и WHOIS данных домена.
// @ID url-check-v2
// @Tags Scan
// @Accept json
// @Produce json
// @Param request body URLCheckRequest true "URL для проверки"
// @Success 200 {object} models.ResponseFromAPI "Успешная проверка URL"
// @Failure 400 {object} common.ErrorResponse "Bad Request: Некорректный запрос или неверный формат URL"
// @Failure 404 {object} common.ErrorResponse "Not Found: Результаты поиска не найдены"
// @Failure 405 {object} common.ErrorResponse "Method Not Allowed: Разрешен только POST метод"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
//
//	@Example 200 Success {
//	  "Zone": "Green",
//	  "Categories": ["CATEGORY_INFORMATION_TECHNOLOGIES", "CATEGORY_SEARCH_ENGINES_AND_SERVICES"],
//	  "UrlGeneralInfo": {
//	    "Url": "https://www.example.com",
//	    "Host": "www.example.com",
//	    "FilesCount": 0,
//	    "Ipv4Count": 100,
//	    "Categories": ["technology", "search"]
//	  },
//	  "UrlDomainWhoIs": {
//	    "DomainName": "example.com",
//	    "Created": "1995-08-14T04:00:00Z",
//	    "RegistrationOrganization": "IANA"
//	  }
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "URL is required"
//	}
//
//	@Example 405 Method Not Allowed {
//	  "Message": "Method not allowed"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Internal Server Error"
//	}
//
// @Router /api/v2/scan/url [post]
func (h *Handler) CheckURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	log := h.logger.With(
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote", r.RemoteAddr),
		slog.String("handler", "CheckURL"),
	)

	var req URLCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		log.Error("failed to decode request body", slog.Any("err", err))
		return
	}

	if req.URL == "" {
		common.RespondWithError(w, http.StatusBadRequest, "URL is required")
		log.Error("missing URL parameter")
		return
	}

	// Validate URL format
	inType := "url"
	if _, _, err := h.usecase.DetermineInputType(req.URL); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.InvalidInput)
		log.Error("invalid URL format", slog.Any("err", err))
		return
	}

	userID, _ := h.sessionManager.Get(ctx, "user_id").(int)

	// Try from cache or DB
	if h.tryFromCacheOrDB(ctx, w, inType, req.URL, userID, log) {
		return
	}

	// Fetch from APIs
	final, err := h.fetchFromAPIs(ctx, inType, req.URL, log)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
		return
	}

	// Return response and persist
	h.writeAndPersist(ctx, w, final, inType, req.URL, userID, log)
}

// CheckDomain
// @Summary Проверка домена через Kaspersky и VirusTotal API
// @Description Эндпоинт для проверки домена и получения объединенного ответа с информацией из Kaspersky и VirusTotal API.
// Возвращается информация о домене, включая статистику файлов, URL, категории и WHOIS данные.
// @ID domain-check-v2
// @Tags Scan
// @Accept json
// @Produce json
// @Param request body DomainCheckRequest true "Домен для проверки"
// @Success 200 {object} models.ResponseFromAPI "Успешная проверка домена"
// @Failure 400 {object} common.ErrorResponse "Bad Request: Некорректный запрос или неверный формат домена"
// @Failure 404 {object} common.ErrorResponse "Not Found: Результаты поиска не найдены"
// @Failure 405 {object} common.ErrorResponse "Method Not Allowed: Разрешен только POST метод"
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
//	    "Domain": "example.com",
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
//	    "DomainName": "example.com",
//	    "Created": "1999-07-11T20:00:00Z",
//	    "Updated": "2021-01-01T00:00:00Z",
//	    "Expires": "2025-07-30T21:00:00Z",
//	    "NameServers": ["ns1.example.com", "ns2.example.com"],
//	    "Contacts": [
//	      {
//	        "ContactType": "registrant",
//	        "Organization": "Example Organization"
//	      }
//	    ],
//	    "Registrar": {
//	      "Info": "EXAMPLE-REGISTRAR",
//	      "IanaId": "1234"
//	    },
//	    "DomainStatus": ["REGISTERED, DELEGATED, VERIFIED"],
//	    "RegistrationOrganization": "EXAMPLE-REGISTRAR"
//	  }
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "Domain is required"
//	}
//
//	@Example 405 Method Not Allowed {
//	  "Message": "Method not allowed"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Internal Server Error"
//	}
//
// @Router /api/v2/scan/domain [post]
func (h *Handler) CheckDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	log := h.logger.With(
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("remote", r.RemoteAddr),
		slog.String("handler", "CheckDomain"),
	)

	var req DomainCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.BadRequestMsg)
		log.Error("failed to decode request body", slog.Any("err", err))
		return
	}

	if req.Domain == "" {
		common.RespondWithError(w, http.StatusBadRequest, "Domain is required")
		log.Error("missing domain parameter")
		return
	}

	// Validate domain format
	inType := "domain"
	if _, _, err := h.usecase.DetermineInputType(req.Domain); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, models.InvalidInput)
		log.Error("invalid domain format", slog.Any("err", err))
		return
	}

	userID, _ := h.sessionManager.Get(ctx, "user_id").(int)

	// Try from cache or DB
	if h.tryFromCacheOrDB(ctx, w, inType, req.Domain, userID, log) {
		return
	}

	// Fetch from APIs
	final, err := h.fetchFromAPIs(ctx, inType, req.Domain, log)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, models.InternalServerErrorMsg)
		return
	}

	// Return response and persist
	h.writeAndPersist(ctx, w, final, inType, req.Domain, userID, log)
}

// Common function to fetch from APIs (extracted from original logic)
func (h *Handler) fetchFromAPIs(ctx context.Context, inType, param string, log *slog.Logger) (models.ResponseFromAPI, error) {
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
			cancel() // interrupt second goroutine
			return final, nil
		}
		if i == 1 {
			log.Error("both API calls failed", slog.Any("last_err", rlt.err))
			return final, rlt.err
		}
	}

	return final, nil
}
