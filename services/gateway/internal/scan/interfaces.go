package scan

import (
	"context"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

type Usecase interface {
	DetermineInputType(input string) (string, string, error)

	GetTextOCRResponse(OCR models.ApiResponse) ([]string, error)
	RequestKasperskyAPI(ctx context.Context, ioc string, apiKey string) (*models.ResponseFromAPI, error)

	CachedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error

	SavedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SaveResponse(ctx context.Context, respJson, zone, inputType, requestParam string, userID int) error
	SaveUserStats(ctx context.Context, zone, inputType, requestParam string, userID int) error
}

type Redis interface {
	GetCachedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error
}

type Postgres interface {
	GetSavedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SaveResponse(ctx context.Context, respJson, inputType, requestParam string) error
	SaveUserResponse(ctx context.Context, userID int, zone, inputType, requestParam string) error
}
