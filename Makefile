# Makefile

# Переменные для путей
DOCKER_COMPOSE_PATH=build/docker-compose.yml
SWAGGER_PATH=./services/gateway/cmd/main.go

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
	