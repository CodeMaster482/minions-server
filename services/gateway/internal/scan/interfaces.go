package scan

import "context"

type Usecase interface {
	DetermineInputType(input string) (string, error)

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
