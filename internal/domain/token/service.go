package token

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// PKCEVerifier validates PKCE code_challenge / code_verifier pairs.
// Only S256 is accepted; the plain method is insecure and rejected.
// See RFC 7636 for the full specification.
type PKCEVerifier struct{}

func NewPKCEVerifier() *PKCEVerifier { return &PKCEVerifier{} }

// Verify returns nil if the code_verifier correctly produces the stored code_challenge.
// method must be "S256"; any other value is rejected to prevent downgrade attacks.
func (v *PKCEVerifier) Verify(codeVerifier, codeChallenge, method string) error {
	if strings.ToUpper(method) != "S256" {
		return apperrors.InvalidInput(
			fmt.Sprintf("unsupported PKCE method %q; only S256 is accepted", method),
			nil,
		)
	}

	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return apperrors.InvalidInput("code_verifier length must be between 43 and 128 characters", nil)
	}

	// S256: BASE64URL(SHA256(ASCII(code_verifier))) must equal code_challenge.
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	if computed != codeChallenge {
		return apperrors.InvalidInput("PKCE code_verifier does not match code_challenge", nil)
	}

	return nil
}
