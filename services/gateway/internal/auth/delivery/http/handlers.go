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
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to register")
		return
	}

	common.RespondWithJSON(w, http.StatusCreated, map[string]string{"message": "User registered"})
}

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

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	err := h.sessionManager.Destroy(r.Context())
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to logout")
		return
	}

	common.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Logout successful"})
}
