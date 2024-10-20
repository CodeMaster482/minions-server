package common

import (
	"encoding/json"
	"net/http"
)

// RespondWithError отправляет ошибку в формате JSON с указанным статусом и сообщением
func RespondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	errorResponse := ErrorResponse{
		Message: message,
	}
	json.NewEncoder(w).Encode(errorResponse)
}
