package statistics

import (
	"context"
	"time"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
)

type Usecase interface {
	GetTopLinksByUserAndPeriod(ctx context.Context, userID *int, period string, zone string, limit int) ([]models.LinkStat, error)
	GetTopLinksByZone(ctx context.Context, zone string, limit int) ([]models.LinkStat, error)
}

type Repo interface {
	TopLinksByUserZoneAndPeriod(ctx context.Context, userID *int, zone string, since time.Time, limit int) ([]models.LinkStat, error)
	TopLinksByZone(ctx context.Context, zone string, limit int) ([]models.LinkStat, error)
}
