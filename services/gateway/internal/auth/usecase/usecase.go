package usecase

import (
	"context"
	"errors"
	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/auth"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

type Usecase struct {
	postgresRepo auth.Repo
	logger       *slog.Logger
}

func New(postgresRepo auth.Repo, logger *slog.Logger) *Usecase {
	return &Usecase{
		postgresRepo: postgresRepo,
		logger:       logger,
	}
}

func (uc *Usecase) Register(ctx context.Context, user common.User) (*common.User, error) {
	existingUser, err := uc.postgresRepo.GetUserByUsername(ctx, user.Username)
	if err != nil {
		uc.logger.Warn(err.Error())

		if existingUser != nil {
			return nil, errors.New("user already exists")
		}
	}

	return uc.postgresRepo.CreateUser(ctx, user)
}

func (uc *Usecase) Authenticate(ctx context.Context, username, password string) (*common.User, error) {
	user, err := uc.postgresRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Проверка пароля
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, err
	}

	return user, nil
}
