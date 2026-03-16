package unit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/enterprise/sso-identity-hub/internal/domain/token"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

func TestPKCEVerifier_ValidS256Challenge(t *testing.T) {
	v := token.NewPKCEVerifier()

	// Pre-computed test vector: verifier → SHA256 → base64url
	// Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (43 chars, RFC 7636 example)
	// Challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" (base64url of SHA256)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	err := v.Verify(verifier, challenge, "S256")
	require.NoError(t, err)
}

func TestPKCEVerifier_RejectsPlainMethod(t *testing.T) {
	v := token.NewPKCEVerifier()

	err := v.Verify("someverifier", "somechallenge", "plain")
	require.Error(t, err)
	assert.ErrorIs(t, err, apperrors.ErrInvalidInput)
}

func TestPKCEVerifier_RejectsMismatch(t *testing.T) {
	v := token.NewPKCEVerifier()

	err := v.Verify(
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"WRONG_CHALLENGE_VALUE_XXXXXXXXXXXXXXXXXXXXXXXXX",
		"S256",
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, apperrors.ErrInvalidInput)
}

func TestPKCEVerifier_RejectsTooShortVerifier(t *testing.T) {
	v := token.NewPKCEVerifier()

	// RFC 7636 requires verifier to be at least 43 characters
	err := v.Verify("short", "anychallenge", "S256")
	require.Error(t, err)
	assert.ErrorIs(t, err, apperrors.ErrInvalidInput)
}

func TestPKCEVerifier_RejectsTooLongVerifier(t *testing.T) {
	v := token.NewPKCEVerifier()

	// RFC 7636 requires verifier to be at most 128 characters
	longVerifier := make([]byte, 129)
	for i := range longVerifier {
		longVerifier[i] = 'a'
	}

	err := v.Verify(string(longVerifier), "anychallenge", "S256")
	require.Error(t, err)
	assert.ErrorIs(t, err, apperrors.ErrInvalidInput)
}

func TestPKCEVerifier_AcceptsUppercaseMethod(t *testing.T) {
	v := token.NewPKCEVerifier()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// Spec allows "S256" or "s256" — our implementation normalises to uppercase.
	err := v.Verify(verifier, challenge, "s256")
	require.NoError(t, err)
}
