package http

import (
	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/auth"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/auth/models"
	"github.com/alexedwards/scs/v2"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
)

type Handler struct {
	usecase        auth.Usecase
	logger         *slog.Logger
	sessionManager *scs.SessionManager
}

func New(uc auth.Usecase, sessionManager *scs.SessionManager, logger *slog.Logger) *Handler {
	return &Handler{
		usecase:        uc,
		sessionManager: sessionManager,
		logger:         logger,
	}
}

// Register
// @Summary Регистрация нового пользователя
// @Description Эндпоинт для регистрации нового пользователя с указанием имени пользователя и пароля
// @ID auth-register
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.UserCredentials true "Учетные данные пользователя для регистрации" example({"username": "user123", "password": "securepassword"})
// @Success 201 {object} string "Пользователь успешно зарегистрирован"
// @Failure 400 {object} common.ErrorResponse "Bad Request: Invalid input"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error: Failed to register"
//
//	@Example 201 Success {
//	  "message": "User registered"
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "Invalid input"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Failed to register"
//	}
//
// @Router /api/auth/register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var creds models.UserCredentials
	if err := common.DecodeJSONBody(w, r, &creds); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validator.New().Struct(creds); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to register")
		return
	}

	user := common.User{
		Username: creds.Username,
		Password: string(hashedPassword),
	}

	if err := h.usecase.Register(r.Context(), user); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, "Failed to register")
		return
	}

	common.RespondWithJSON(w, http.StatusCreated, map[string]string{"message": "User registered"})
}

// Login
// @Summary Вход пользователя
// @Description Эндпоинт для аутентификации пользователя с указанием имени пользователя и пароля
// @ID auth-login
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.UserCredentials true "Учетные данные пользователя для входа" example({"username": "user123", "password": "securepassword"})
// @Success 200 {object} map[string]string "Успешный вход пользователя"
// @Failure 400 {object} common.ErrorResponse "Bad Request: Invalid input"
// @Failure 401 {object} common.ErrorResponse "Unauthorized: Invalid credentials"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
//
//	@Example 200 Success {
//	  "message": "Login successful"
//	}
//
//	@Example 400 Bad Request {
//	  "Message": "Invalid input"
//	}
//
//	@Example 401 Unauthorized {
//	  "Message": "Invalid credentials"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Internal Server Error"
//	}
//
// @Router /api/auth/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var creds models.UserCredentials
	if err := common.DecodeJSONBody(w, r, &creds); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validator.New().Struct(creds); err != nil {
		common.RespondWithError(w, http.StatusBadRequest, "Invalid input")
		return
	}

	user, err := h.usecase.Authenticate(r.Context(), creds.Username, creds.Password)
	if err != nil {
		common.RespondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	h.sessionManager.Put(r.Context(), "user_id", user.ID)
	h.sessionManager.Put(r.Context(), "username", user.Username)

	// Return CSRF token
	//csrfToken := csrf.Token(r)
	common.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Login successful",
		//"csrf_token": csrfToken,
	})
}

// Logout
// @Summary Выход пользователя
// @Description Эндпоинт для выхода пользователя и уничтожения его сессии
// @ID auth-logout
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "Успешный выход пользователя"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error: Failed to logout"
//
//	@Example 200 Success {
//	  "message": "Logout successful"
//	}
//
//	@Example 500 Internal Server Error {
//	  "Message": "Failed to log out"
//	}
//
// @Router /api/auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	err := h.sessionManager.Destroy(r.Context())
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to logout")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Logout successful"})
}
