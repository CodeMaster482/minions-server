package v1

import (
	"log/slog"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan"
	"github.com/alexedwards/scs/v2"
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

func NewService(apiKey string, vtApiKey, iamToken string, folderID string, uc scan.Usecase, sessionManager *scs.SessionManager, logger *slog.Logger) *Handler {
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
