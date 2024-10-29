package common

// ErrorResponse представляет ответ с ошибкой
type ErrorResponse struct {
	// Сообщение об ошибке
	Message string `json:"message"`
}
