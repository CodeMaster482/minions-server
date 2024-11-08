package middleware

import (
	"github.com/CodeMaster482/minions-server/common"
	"github.com/alexedwards/scs/v2"
	"github.com/gorilla/mux"
	"log/slog"
	"net/http"
	"time"
)

type Middleware struct {
	SessionManager *scs.SessionManager
}

func New(sessionManager *scs.SessionManager) *Middleware {
	return &Middleware{
		SessionManager: sessionManager,
	}
}

func (m *Middleware) Recovery(logger *slog.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("Recovered from panic", slog.Any("panic", rec))
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) Logging(logger *slog.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			duration := time.Since(start).Seconds()
			logger.Info("Handled request",
				slog.String("method", r.Method),
				slog.String("url", r.URL.String()),
				slog.String("remote_addr", r.RemoteAddr),
				slog.Float64("duration_seconds", duration),
			)
		})
	}
}

func (m *Middleware) Cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-api-key")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) SessionTimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastActive, ok := m.SessionManager.Get(r.Context(), "last_active").(time.Time)
		if ok && time.Since(lastActive) > m.SessionManager.IdleTimeout {
			// Сессия истекла
			err := m.SessionManager.Destroy(r.Context())
			if err != nil {
				common.RespondWithError(w, http.StatusInternalServerError, "Failed to destroy session")
				return
			}
			common.RespondWithError(w, http.StatusUnauthorized, "Session expired")
			return
		}

		// Обновляем время последней активности
		m.SessionManager.Put(r.Context(), "last_active", time.Now())

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := m.SessionManager.GetInt(r.Context(), "user_id")
		if userID == 0 {
			common.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

//func (m *Middleware) CSRFTokenMiddleware(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		csrfToken := csrf.Token(r)
//		w.Header().Set("X-CSRF-Token", csrfToken)
//		next.ServeHTTP(w, r)
//	})
//}
