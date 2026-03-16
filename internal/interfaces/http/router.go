// Package http contains the Gin router setup and all route registrations.
package http

import (
	"github.com/gin-gonic/gin"

	"github.com/enterprise/sso-identity-hub/internal/application/auth"
	"github.com/enterprise/sso-identity-hub/internal/application/logout"
	"github.com/enterprise/sso-identity-hub/internal/application/provisioning"
	"github.com/enterprise/sso-identity-hub/internal/config"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/interfaces/http/handlers"
	"github.com/enterprise/sso-identity-hub/internal/interfaces/http/middleware"
	"go.uber.org/zap"
)

// RouterDeps groups all handler and middleware dependencies for clean injection.
type RouterDeps struct {
	AuthSvc         *auth.Service
	LogoutSvc       *logout.Service
	SessionSvc      *session.Service
	ProvisioningSvc *provisioning.Service
	JWKSPayload     gin.H
	Cfg             config.Config
	Logger          *zap.Logger
}

// NewRouter builds and returns a configured Gin engine.
// Route grouping mirrors REST conventions; admin routes are separated
// from the user-facing OIDC endpoints.
func NewRouter(deps RouterDeps) *gin.Engine {
	if deps.Cfg.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Global middleware — order matters: recovery first so panics are always caught.
	r.Use(middleware.Recovery(deps.Logger))
	r.Use(middleware.RequestLogger(deps.Logger))
	r.Use(middleware.RateLimiter(deps.Cfg.RateLimit.RequestsPerMinute, deps.Logger))

	// --- Public routes (no session required) ---
	r.GET("/healthz", handlers.HealthCheck)
	r.GET("/.well-known/jwks.json", handlers.NewJWKSHandler(deps.JWKSPayload).ServeJWKS)

	authH := handlers.NewAuthHandler(deps.AuthSvc)
	r.GET("/auth/callback", authH.HandleCallback)
	r.POST("/auth/callback", authH.HandleCallback)

	// --- Authenticated routes ---
	protected := r.Group("/")
	protected.Use(middleware.RequireSession(deps.SessionSvc))
	{
		protected.GET("/auth/me", handlers.WhoAmI)

		logoutH := handlers.NewLogoutHandler(deps.LogoutSvc)
		protected.POST("/auth/logout", logoutH.Logout)
		protected.POST("/auth/logout/all", logoutH.LogoutAll)

		sessH := handlers.NewSessionHandler(deps.SessionSvc)
		protected.GET("/sessions/current", sessH.GetSession)
		protected.GET("/sessions", sessH.ListUserSessions)
		protected.DELETE("/sessions/:session_id", sessH.RevokeSession)
	}

	// --- Admin routes ---
	admin := r.Group("/admin")
	admin.Use(middleware.RequireSession(deps.SessionSvc))
	{
		logoutH := handlers.NewLogoutHandler(deps.LogoutSvc)
		admin.POST("/users/:user_id/logout", logoutH.AdminForceLogout)

		scimH := handlers.NewSCIMHandler(deps.ProvisioningSvc)
		admin.POST("/users/:user_id/provision", scimH.ProvisionUser)
		admin.POST("/users/:user_id/deprovision", scimH.DeprovisionUser)
	}

	return r
}
