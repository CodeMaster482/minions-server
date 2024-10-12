package main

import (
	"errors"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"time"
)

type Config struct {
	Address           string        `yaml:"address"`
	Timeout           time.Duration `yaml:"timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	KasperskyAPIKey   string        `yaml:"kaspersky_api_key"`
	LogFormat         string        `yaml:"log_format"`
}

// LoadConfig загружает конфигурацию из YAML-файла и устанавливает дефолтные значения, если они не заданы
func LoadConfig(filename string) (*Config, error) {
	cfg := &Config{
		Address:           ":8080",
		Timeout:           15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		LogFormat:         "json",
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

	if cfg.Address == "" {
		cfg.Address = ":8080"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = 5 * time.Second
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "json"
	}
	if cfg.KasperskyAPIKey == "" {
		// Если API-ключ не задан в конфигурации, пытаемся получить его из переменной окружения
		cfg.KasperskyAPIKey = os.Getenv("KASPERSKY_API_KEY")
		if cfg.KasperskyAPIKey == "" {
			return nil, errors.New("Kaspersky API key is not provided in config file or environment variable")
		}
	}

	return cfg, nil
}
