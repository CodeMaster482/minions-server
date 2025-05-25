package v2

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"github.com/alexedwards/scs/v2"
)

func NewService(apiKey, vtApiKey, iamToken, folderID string, uc scan.Usecase, sm *scs.SessionManager, logger *slog.Logger) *Handler {
	return &Handler{
		iamToken:       iamToken,
		folderID:       folderID,
		apiKey:         apiKey,
		vtApiKey:       vtApiKey,
		usecase:        uc,
		sessionManager: sm,
		logger:         logger,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

type Handler struct {
	iamToken       string
	apiKey         string
	vtApiKey       string
	folderID       string
	usecase        scan.Usecase
	sessionManager *scs.SessionManager
	logger         *slog.Logger
	httpClient     *http.Client
}
