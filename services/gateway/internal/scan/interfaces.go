package scan

import (
	"context"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/scan/models"
)

type Usecase interface {
	DetermineInputType(input string) (string, error)
	GetTextOCRResponse(OCR models.OCRResponse) ([]string, error)
	RequestKasperskyAPI()
	CachedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error

	SavedResponse(ctx context.Context, inputType, requestParam string) (string, error)
}

type Redis interface {
	GetCachedResponse(ctx context.Context, inputType, requestParam string) (string, error)
	SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error
}

type Postgres interface {
	GetSavedResponse(ctx context.Context, inputType, requestParam string) (string, error)
}