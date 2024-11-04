package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

var (
	GetScanResults = `
        SELECT response FROM scan_results
        WHERE input_type = $1 AND request = $2
        FOR UPDATE
    `
	UpdateScanResults = `
        UPDATE scan_results
        SET access_count = access_count + 1
        WHERE input_type = $1 AND request = $2
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

// GetSavedResponse берем сохраненный ответ из PostgreSQL и обновляем access_count
func (p *Postgres) GetSavedResponse(ctx context.Context, inputType, requestParam string) (string, error) {
	p.logger.Debug("Starting GetSavedResponse",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		p.logger.Error("Failed to begin transaction",
			slog.Any("error", err),
		)

		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			p.logger.Error("Failed to rollback transaction",
				slog.Any("error", err),
			)
		}
	}()

	var savedResponse string
	err = tx.QueryRowContext(ctx, GetScanResults, inputType, requestParam).Scan(&savedResponse)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			p.logger.Info("Record not found in PostgreSQL")

			return "", nil
		}

		p.logger.Error("Error executing SELECT query in PostgreSQL",
			slog.Any("error", err),
		)

		return "", fmt.Errorf("error executing SELECT query: %w", err)
	}

	p.logger.Debug("Record found in PostgreSQL, updating access_count")

	_, err = tx.ExecContext(ctx, UpdateScanResults, inputType, requestParam)
	if err != nil {
		p.logger.Error("Error updating access_count in PostgreSQL",
			slog.Any("error", err),
		)

		return "", fmt.Errorf("error updating access_count: %w", err)
	}

	if err := tx.Commit(); err != nil {
		p.logger.Error("Failed to commit transaction in PostgreSQL",
			slog.Any("error", err),
		)

		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	p.logger.Info("Successfully retrieved and updated response from PostgreSQL")

	return savedResponse, nil
}
