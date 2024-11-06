package main

import (
	"errors"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Gateway  GatewayConfig  `yaml:"gateway"`
	Postgres PostgresConfig `yaml:"postgres"`
	Redis    RedisConfig    `yaml:"redis"`
}
type GatewayConfig struct {
	Address           string        `yaml:"address"`
	Timeout           time.Duration `yaml:"timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	KasperskyAPIKey   string        `yaml:"kaspersky_api_key"`
	IamToken          string        `yaml:"iam_token"`
	FolderID          string        `yaml:"folder_id"`
	LogFormat         string        `yaml:"log_format"`
	LogFile           string        `yaml:"log_file"`
}
type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// LoadConfig загружает конфигурацию из YAML-файла и устанавливает дефолтные значения, если они не заданы
func LoadConfig(filename string) (*Config, error) {
	cfg := &Config{
		Gateway: GatewayConfig{
			Address:           ":8080",
			Timeout:           15 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			LogFormat:         "json",
			FolderID:          "ajel4b7rb4q4525ph1am",
			LogFile:           "", // По умолчанию пустой, значит логи будут только в консоль
		},
		Postgres: PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			DBName:   "minions",
			SSLMode:  "disable",
		},
		Redis: RedisConfig{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		},
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Если файл не найден, используем дефолтные значения
			log.Printf("Config file %s not found, using default values\n", filename)
			return cfg, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	// Устанавливаем значения по умолчанию, если они не заданы в конфиге

	// Параметры сервера
	if cfg.Gateway.Address == "" {
		cfg.Gateway.Address = ":8080"
	}
	if cfg.Gateway.Timeout == 0 {
		cfg.Gateway.Timeout = 15 * time.Second
	}
	if cfg.Gateway.IdleTimeout == 0 {
		cfg.Gateway.IdleTimeout = 60 * time.Second
	}
	if cfg.Gateway.ReadHeaderTimeout == 0 {
		cfg.Gateway.ReadHeaderTimeout = 5 * time.Second
	}
	if cfg.Gateway.LogFormat == "" {
		cfg.Gateway.LogFormat = "json"
	}

	// Kaspersky API Key
	if cfg.Gateway.KasperskyAPIKey == "" {
		// Если API-ключ не задан в конфигурации, пытаемся получить его из переменной окружения
		cfg.Gateway.KasperskyAPIKey = os.Getenv("KASPERSKY_API_KEY")
		if cfg.Gateway.KasperskyAPIKey == "" {
			return nil, errors.New("kaspersky API key is not provided in config file or environment variable")
		}
	}

	// IAM_TOKEN API Key
	if cfg.Gateway.IamToken == "" {
		// Если API-ключ не задан в конфигурации, пытаемся получить его из переменной окружения
		cfg.Gateway.IamToken = os.Getenv("IAM_TOKEN")
		if cfg.Gateway.IamToken == "" {
			return nil, errors.New("yandex API key is not provided in config file or environment variable")
		}
	}

	// Конфигурация базы данных PostgreSQL
	if cfg.Postgres.Host == "" {
		cfg.Postgres.Host = "localhost"
	}
	if cfg.Postgres.Port == 0 {
		cfg.Postgres.Port = 5432
	}
	if cfg.Postgres.User == "" {
		cfg.Postgres.User = "postgres"
	}
	if cfg.Postgres.Password == "" {
		cfg.Postgres.Password = "postgres"
	}
	if cfg.Postgres.DBName == "" {
		cfg.Postgres.DBName = "minions"
	}
	if cfg.Postgres.SSLMode == "" {
		cfg.Postgres.SSLMode = "disable"
	}

	// Конфигурация redis
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "localhost:6379"
	}
	if cfg.Redis.Password == "" {
		cfg.Redis.Password = "redis"
	}
	if cfg.Redis.DB == 0 {
		cfg.Redis.DB = 0
	}

	return cfg, nil
}
