package repo

import (
	"context"
	"database/sql"
	"errors"
	"github.com/CodeMaster482/minions-server/common"
	"log/slog"
)

var (
	CreateUser = `
        INSERT INTO users (username, password)
        VALUES ($1, $2)
        RETURNING id;
    `
	GetUserByName = `
        SELECT id, username, password
        FROM users
        WHERE username = $1;
    `
)

type Repo struct {
	db     *sql.DB
	logger *slog.Logger
}

func New(db *sql.DB, logger *slog.Logger) *Repo {
	return &Repo{
		db:     db,
		logger: logger,
	}
}

func (r *Repo) CreateUser(ctx context.Context, u common.User) error {
	err := r.db.QueryRowContext(ctx, CreateUser, u.Username, u.Password).Scan(&u.ID)
	if err != nil {
		r.logger.Error("Failed to create user", slog.Any("error", err))
		return err
	}

	return nil
}

func (r *Repo) GetUserByUsername(ctx context.Context, username string) (*common.User, error) {
	u := &common.User{}
	err := r.db.QueryRowContext(ctx, GetUserByName, username).Scan(u.ID, u.Username, u.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}

		r.logger.Error("Failed to get user by username", slog.Any("error", err))
		return nil, err
	}

	return u, nil
}
