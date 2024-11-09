package repo

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
	"log/slog"
)

var (
	TopLinksByZone = `
        SELECT request, access_count
        FROM scan_results
        WHERE response->>'Zone' = $1
        ORDER BY access_count DESC
        LIMIT $2
    `
)

type Postgres struct {
	db     *sql.DB
	logger *slog.Logger
}

func New(db *sql.DB, logger *slog.Logger) *Postgres {
	return &Postgres{
		db:     db,
		logger: logger,
	}
}

// TopLinksByZone возвращает топ-N ссылок для указанной зоны
func (p *Postgres) TopLinksByZone(ctx context.Context, zone string, limit int) ([]models.LinkStat, error) {
	rows, err := p.db.QueryContext(ctx, TopLinksByZone, zone, limit)
	if err != nil {
		p.logger.Error("Error executing TOP links query", slog.Any("error", err))
		return nil, fmt.Errorf("error executing top links query: %w", err)
	}
	defer rows.Close()

	var results []models.LinkStat
	for rows.Next() {
		var stat models.LinkStat
		if err := rows.Scan(&stat.Request, &stat.AccessCount); err != nil {
			p.logger.Error("Error scanning row", slog.Any("error", err))
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		results = append(results, stat)
	}

	if err := rows.Err(); err != nil {
		p.logger.Error("Rows iteration error", slog.Any("error", err))
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return results, nil
}
