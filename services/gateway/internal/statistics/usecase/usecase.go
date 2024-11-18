package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
	"log/slog"
)

type Usecase struct {
	repo   statistics.Repo
	logger *slog.Logger
}

func New(repo statistics.Repo, logger *slog.Logger) *Usecase {
	return &Usecase{
		repo:   repo,
		logger: logger,
	}
}

// GetTopLinksByUserAndPeriod returns top N links for a user, period, and zone
func (uc *Usecase) GetTopLinksByUserAndPeriod(ctx context.Context, userID *int, period string, zone string, limit int) ([]models.LinkStat, error) {
	var since time.Time
	now := time.Now()
	switch period {
	case "day":
		since = now.AddDate(0, 0, -1)
	case "week":
		since = now.AddDate(0, 0, -7)
	case "month":
		since = now.AddDate(0, -1, 0)
	default:
		return nil, fmt.Errorf("invalid period: %s", period)
	}

	stats, err := uc.repo.TopLinksByUserZoneAndPeriod(ctx, userID, zone, since, limit)
	if err != nil {
		uc.logger.Error("Error getting top links", slog.Any("error", err))
		return nil, fmt.Errorf("error getting top links: %w", err)
	}

	return stats, nil
}

// GetTopLinksByZone returns top N links for a zone over all time
func (uc *Usecase) GetTopLinksByZone(ctx context.Context, zone string, limit int) ([]models.LinkStat, error) {
	stats, err := uc.repo.TopLinksByZone(ctx, zone, limit)
	if err != nil {
		uc.logger.Error("Error getting top links by zone", slog.Any("error", err))
		return nil, fmt.Errorf("error getting top links by zone: %w", err)
	}

	return stats, nil
}
