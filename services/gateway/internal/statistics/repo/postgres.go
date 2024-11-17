package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
	"log/slog"
)

var (
	// Updated query to include user_id and time period
	TopLinksByUserZoneAndPeriod = `
        SELECT request, SUM(access_count) as total_access_count
        FROM scan_results
        WHERE (user_id = $1 OR ($1 IS NULL AND user_id IS NULL))
          AND response->>'Zone' = $2
          AND created_at >= $3
        GROUP BY request
        ORDER BY total_access_count DESC
        LIMIT $4
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

// TopLinksByUserZoneAndPeriod returns the top N links for a user, zone, and time period
func (p *Postgres) TopLinksByUserZoneAndPeriod(ctx context.Context, userID *int, zone string, since time.Time, limit int) ([]models.LinkStat, error) {
	rows, err := p.db.QueryContext(ctx, TopLinksByUserZoneAndPeriod, userID, zone, since, limit)
	if err != nil {
		p.logger.Error("Error executing top links query", slog.Any("error", err))
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
