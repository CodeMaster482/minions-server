package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

const (
	PostgresMaxRecords = 10000
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

	SaveScanResults = `
	   INSERT INTO scan_results (input_type, request, response, access_count, created_at)
	   VALUES ($1, $2, $3, 1, NOW())
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

func (p *Postgres) SaveResponse(ctx context.Context, responseJson, inputType, requestParam string) error {
	p.logger.Debug("Starting SaveResponse",
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		p.logger.Error("Ошибка при начале транзакции", slog.Any("error", err))

		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Сохраняем в PostgreSQL с начальным access_count = 1
	_, err = tx.ExecContext(ctx, SaveScanResults, inputType, requestParam, responseJson)
	if err != nil {

		p.logger.Error("Ошибка при вставке в PostgreSQL", slog.Any("error", err))

		return fmt.Errorf("error executing INSERT query: %w", err)
	}

	// Проверяем количество записей и очищаем, если превышен лимит
	err = p.cleanupLeastPopularRecords(ctx, tx)
	if err != nil {
		p.logger.Error("Ошибка при очистке записей в PostgreSQL", slog.Any("error", err))

		return fmt.Errorf("error executing cleanupLeastPopularRecords: %w", err)
	}

	// Фиксируем транзакцию
	if err := tx.Commit(); err != nil {
		p.logger.Error("Ошибка при фиксации транзакции", slog.Any("error", err))

		return fmt.Errorf("error executing INSERT query: %w", err)
	}

	p.logger.Info("Successfully retrieved and updated response from PostgreSQL")

	return nil

}

// Функция для очистки самых непопулярных записей в PostgreSQL
func (p *Postgres) cleanupLeastPopularRecords(ctx context.Context, tx *sql.Tx) error {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_results").Scan(&count)
	if err != nil {
		p.logger.Error("Ошибка при подсчете записей в PostgreSQL", slog.Any("error", err))
		return err
	}

	if count > PostgresMaxRecords {
		// Вычисляем количество записей для удаления
		deleteCount := count - PostgresMaxRecords

		// Удаляем записи с наименьшим значением access_count
		_, err = tx.ExecContext(ctx, `
            DELETE FROM scan_results
            WHERE id IN (
                SELECT id FROM scan_results
                ORDER BY access_count ASC, created_at ASC
                LIMIT $1
                FOR UPDATE
            )
        `, deleteCount)
		if err != nil {
			p.logger.Error("Ошибка при удалении непопулярных записей в PostgreSQL", slog.Any("error", err))
			return err
		} else {
			p.logger.Info("Удалены непопулярные записи из PostgreSQL", slog.Int("deleted_records", deleteCount))
		}
	}
	return nil
}
