package auth

import (
	"context"
	"github.com/CodeMaster482/minions-server/common"
)

type Usecase interface {
	Register(ctx context.Context, user common.User) error
	Authenticate(ctx context.Context, username, password string) (*common.User, error)
}

type Repo interface {
	CreateUser(ctx context.Context, user common.User) error
	GetUserByUsername(ctx context.Context, username string) (*common.User, error)
}
