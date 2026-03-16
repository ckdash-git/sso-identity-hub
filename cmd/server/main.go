// Package main is the application entrypoint. It wires all dependencies using
// constructor injection, starts the HTTP server, and handles graceful shutdown.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/enterprise/sso-identity-hub/internal/application/auth"
	"github.com/enterprise/sso-identity-hub/internal/application/logout"
	"github.com/enterprise/sso-identity-hub/internal/application/provisioning"
	"github.com/enterprise/sso-identity-hub/internal/config"
	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/domain/token"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/casdoor"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database/repository"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/msgraph"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/scim"
	httpinterfaces "github.com/enterprise/sso-identity-hub/internal/interfaces/http"
	pkgcrypto "github.com/enterprise/sso-identity-hub/pkg/crypto"
	pkgjwt "github.com/enterprise/sso-identity-hub/pkg/jwt"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.Log)
	defer logger.Sync() //nolint:errcheck

	// --- Infrastructure: Database ---
	db, err := database.Connect(cfg.Postgres)
	if err != nil {
		logger.Fatal("database connection failed", zap.Error(err))
	}
	if err := database.RunMigrations(cfg.Postgres.URL(), "./migrations"); err != nil {
		logger.Fatal("database migration failed", zap.Error(err))
	}

	// --- Infrastructure: Casdoor IdP ---
	casdoorClient, err := casdoor.NewClient(cfg.Casdoor)
	if err != nil {
		logger.Fatal("casdoor client init failed", zap.Error(err))
	}

	// --- Infrastructure: MS Graph (optional — skip if not configured) ---
	var graphClient *msgraph.Client
	if cfg.MSGraph.TenantID != "" {
		graphClient = msgraph.NewClient(cfg.MSGraph)
	}

	// --- Infrastructure: SCIM ---
	scimClient := scim.NewClient(cfg.SCIM)

	// --- PKG: RSA Keys for RS256 JWT signing ---
	privateKey, err := pkgcrypto.LoadRSAPrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		logger.Fatal("load rsa private key failed", zap.Error(err))
	}
	publicKey, err := pkgcrypto.LoadRSAPublicKey(cfg.JWT.PublicKeyPath)
	if err != nil {
		logger.Fatal("load rsa public key failed", zap.Error(err))
	}

	jwtSvc := pkgjwt.NewService(privateKey, publicKey, cfg.OIDC.IssuerURL, cfg.JWT.KeyID)

	// --- Domain: Repositories ---
	identityRepo := repository.NewPostgresIdentityRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)

	// --- Domain: Services ---
	identitySvc := identity.NewService(identityRepo)
	sessionSvc := session.NewService(sessionRepo, cfg.TokenPolicy.MaxAgeDuration)
	pkceVerifier := token.NewPKCEVerifier()

	// --- Application: Services ---
	authSvc := auth.NewService(casdoorClient, identitySvc, sessionSvc, pkceVerifier, *cfg)
	logoutSvc := logout.NewService(sessionSvc, identitySvc, jwtSvc, graphClient, nil, *cfg, logger)
	provisioningSvc := provisioning.NewService(identitySvc, scimClient, logger)

	// --- HTTP: Router ---
	jwksPayload := buildJWKSPayload(publicKey, cfg.JWT.KeyID)
	router := httpinterfaces.NewRouter(httpinterfaces.RouterDeps{
		AuthSvc:         authSvc,
		LogoutSvc:       logoutSvc,
		SessionSvc:      sessionSvc,
		ProvisioningSvc: provisioningSvc,
		JWKSPayload:     jwksPayload,
		Cfg:             *cfg,
		Logger:          logger,
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start the server in a goroutine so the main goroutine can listen for signals.
	go func() {
		logger.Info("sso identity hub starting", zap.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server listen failed", zap.Error(err))
		}
	}()

	// Graceful shutdown: wait for SIGINT or SIGTERM, then allow 15s for in-flight requests.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutdown signal received, draining connections")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", zap.Error(err))
	}
	logger.Info("server stopped")
}

// buildLogger constructs a zap.Logger from the log configuration.
func buildLogger(cfg config.LogConfig) *zap.Logger {
	level, _ := zapcore.ParseLevel(cfg.Level)

	var zapCfg zap.Config
	if cfg.Format == "console" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	zapCfg.Level = zap.NewAtomicLevelAt(level)

	logger, err := zapCfg.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to build logger: %v", err))
	}
	return logger
}

// buildJWKSPayload serialises the RSA public key into a JWKS-compatible gin.H map.
// The key is pre-computed at startup to avoid per-request serialisation overhead.
func buildJWKSPayload(pub *rsa.PublicKey, keyID string) gin.H {
	return gin.H{
		"keys": []gin.H{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": keyID,
				// n and e are the RSA modulus and public exponent in base64url encoding.
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
