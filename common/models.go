package common

// ErrorResponse представляет ответ с ошибкой
type ErrorResponse struct {
	// Сообщение об ошибке
	Message string `json:"message"`
}

type User struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
	Password string `json:"password"`
}
