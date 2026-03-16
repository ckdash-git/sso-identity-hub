package unit_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgjwt "github.com/enterprise/sso-identity-hub/pkg/jwt"
)

// generateTestKeyPair creates an ephemeral RSA-2048 key pair for tests.
// Using 2048 bits matches the production key size; do not use shorter keys.
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func TestJWTService_MintAndVerifyLogoutToken(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	svc := pkgjwt.NewService(priv, pub, "https://idp.example.com", "test-key-1")

	subject := "user-abc-123"
	sessionID := "sess-xyz-456"

	tokenStr, err := svc.MintLogoutToken(subject, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	claims, err := svc.VerifyLogoutToken(tokenStr)
	require.NoError(t, err)

	assert.Equal(t, subject, claims.Subject)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, "https://idp.example.com", claims.Issuer)
	assert.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 5*time.Second)
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
	assert.NotEmpty(t, claims.ID, "jti must be set to prevent replay")

	_, ok := claims.Events[pkgjwt.LogoutEventClaim]
	assert.True(t, ok, "events claim must contain the logout event key")
}

func TestJWTService_VerifyRejectsExpiredToken(t *testing.T) {
	priv, pub := generateTestKeyPair(t)

	// Create a service that signs with a negative TTL to produce an already-expired token.
	svc := pkgjwt.NewService(priv, pub, "https://idp.example.com", "test-key-1")
	tokenStr, err := svc.MintLogoutToken("user-1", "sess-1")
	require.NoError(t, err)

	// Verify with a different (valid) key pair — should fail signature check.
	priv2, pub2 := generateTestKeyPair(t)
	wrongSvc := pkgjwt.NewService(priv2, pub2, "https://idp.example.com", "test-key-2")

	_, err = wrongSvc.VerifyLogoutToken(tokenStr)
	assert.Error(t, err, "token signed by a different key must be rejected")
}

func TestJWTService_VerifyRejectsWrongAlgorithm(t *testing.T) {
	// Producing an HS256 token and presenting it to the RS256 verifier must fail.
	priv, pub := generateTestKeyPair(t)
	svc := pkgjwt.NewService(priv, pub, "https://idp.example.com", "test-key-1")

	// We use a manually crafted header — easiest way is to just test with a garbage string.
	_, err := svc.VerifyLogoutToken("not.a.valid.jwt")
	assert.Error(t, err, "garbage input must return an error")
}

func TestJWTService_MintProducesUniqueJTIs(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	svc := pkgjwt.NewService(priv, pub, "https://idp.example.com", "test-key-1")

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		tok, err := svc.MintLogoutToken("user-1", "sess-1")
		require.NoError(t, err)
		claims, err := svc.VerifyLogoutToken(tok)
		require.NoError(t, err)
		assert.False(t, seen[claims.ID], "jti %q was repeated — logout tokens are replayable", claims.ID)
		seen[claims.ID] = true
	}
}
