# Makefile

# Переменные для путей
DOCKER_COMPOSE_PATH=build/docker-compose.yml
SWAGGER_PATH=./services/gateway/cmd/main.go

# Путь к файлу config.yaml
CONFIG_FILE=services/gateway/cmd/config.yaml

# URL для получения iamToken
IAM_TOKEN_URL=https://iam.api.cloud.yandex.net/iam/v1/tokens

# Тело запроса для получения iamToken, использующее переменную окружения
IAM_TOKEN_REQUEST_BODY={"\"yandexPassportOauthToken\":\"$(YANDEX_OAUTH_TOKEN)\""}

# Команда для запуска docker-compose с пересборкой
.PHONY: run
run:
	@echo "Опускаем docker-compose..."
	sudo docker compose -f $(DOCKER_COMPOSE_PATH) down
	@echo "Поднимаем docker-compose с пересборкой..."
	sudo docker compose -f $(DOCKER_COMPOSE_PATH) up --build -d

# Команда для генерации Swagger
.PHONY: swag-gen
swag-gen:
	@echo "Генерация Swagger документации..."
	swag init -g $(SWAGGER_PATH)
	