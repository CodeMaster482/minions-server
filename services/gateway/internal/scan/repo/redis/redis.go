package redis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const RedisCacheExpiration = 24 * time.Hour

type Redis struct {
	redis  *redis.Client
	logger *slog.Logger
}

func New(redis *redis.Client, logger *slog.Logger) *Redis {
	return &Redis{
		redis:  redis,
		logger: logger,
	}
}

func (r *Redis) GetCachedResponse(ctx context.Context, inputType, requestParam string) (string, error) {
	redisKey := fmt.Sprintf("scan:%s:%s", inputType, requestParam)

	r.logger.Debug("Try to get cached response from Redis",
		slog.String("redis_key", redisKey),
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	cachedResponse, err := r.redis.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			r.logger.Info("Cache Miss",
				slog.Any("error", err),
			)

			return "", nil
		}

		r.logger.Error("Invalid error",
			slog.Any("error", err),
		)
		return "", err
	}

	r.logger.Info("Cache Hit")

	return cachedResponse, nil
}

func (r *Redis) SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error {
	redisKey := fmt.Sprintf("scan:%s:%s", inputType, requestParam)

	r.logger.Debug("Attempting to set cached response in Redis",
		slog.String("redis_key", redisKey),
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	err := r.redis.Set(ctx, redisKey, savedResponse, RedisCacheExpiration).Err()
	if err != nil {
		r.logger.Error("Failed to set cached response in Redis",
			slog.Any("error", err),
		)

		return err
	}

	r.logger.Debug("Successfully set cached response in Redis")

	return nil
}
