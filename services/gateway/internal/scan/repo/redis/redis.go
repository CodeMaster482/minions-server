package redis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gomodule/redigo/redis"
)

const RedisCacheExpiration = 24 * time.Hour

type Redis struct {
	redisPool *redis.Pool
	logger    *slog.Logger
}

func New(redisPool *redis.Pool, logger *slog.Logger) *Redis {
	return &Redis{
		redisPool: redisPool,
		logger:    logger,
	}
}

// GetCachedResponse получает кэшированный ответ из Redis
func (r *Redis) GetCachedResponse(ctx context.Context, inputType, requestParam string) (string, error) {
	redisKey := fmt.Sprintf("scan:%s:%s", inputType, requestParam)

	r.logger.Debug("Try to get cached response from Redis",
		slog.String("redis_key", redisKey),
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	conn := r.redisPool.Get()
	defer conn.Close()

	// Выполняем команду GET
	cachedResponse, err := redis.String(conn.Do("GET", redisKey))
	if err != nil {
		if errors.Is(err, redis.ErrNil) {
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

// SetCachedResponse сохраняет ответ в Redis с установленным TTL
func (r *Redis) SetCachedResponse(ctx context.Context, savedResponse, inputType, requestParam string) error {
	redisKey := fmt.Sprintf("scan:%s:%s", inputType, requestParam)

	r.logger.Debug("Attempting to set cached response in Redis",
		slog.String("redis_key", redisKey),
		slog.String("input_type", inputType),
		slog.String("request_param", requestParam),
	)

	conn := r.redisPool.Get()
	defer conn.Close()

	// Используем SETEX для установки значения с TTL
	_, err := conn.Do("SETEX", redisKey, int(RedisCacheExpiration.Seconds()), savedResponse)
	if err != nil {
		r.logger.Error("Failed to set cached response in Redis",
			slog.Any("error", err),
		)
		return err
	}

	r.logger.Debug("Successfully set cached response in Redis")

	return nil
}
