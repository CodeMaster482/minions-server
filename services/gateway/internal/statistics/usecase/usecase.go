package usecase

import (
	"context"
	"fmt"
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

// GetTopLinks возвращает топ-5 популярных ссылок для зон "Red" и "Green"
func (uc *Usecase) GetTopLinks(ctx context.Context, limit int) (map[string][]models.LinkStat, error) {
	zones := []string{"Red", "Green"}
	result := make(map[string][]models.LinkStat)

	for _, zone := range zones {
		stats, err := uc.repo.TopLinksByZone(ctx, zone, limit)
		if err != nil {
			uc.logger.Error("Error getting top links", slog.String("zone", zone), slog.Any("error", err))
			return nil, fmt.Errorf("error getting top links for zone %s: %w", zone, err)
		}
		result[zone] = stats
	}

	return result, nil
}
