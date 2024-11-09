package statistics

import (
	"context"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
)

type Usecase interface {
	GetTopLinks(ctx context.Context, limit int) (map[string][]models.LinkStat, error)
}

type Repo interface {
	TopLinksByZone(ctx context.Context, zone string, limit int) ([]models.LinkStat, error)
}
