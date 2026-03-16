// Package crypto provides helpers for loading and managing asymmetric key material.
package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadRSAPrivateKey reads a PEM-encoded RSA private key from disk.
// The server uses this key to sign RS256 logout tokens so that receiving
// parties can verify authenticity using the corresponding public key via JWKS.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	// Support both PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY) formats.
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		return key, nil

	case "PRIVATE KEY":
		keyI, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		rsaKey, ok := keyI.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not an RSA key")
		}
		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}
}

// LoadRSAPublicKey reads a PEM-encoded RSA public key (PKIX / SubjectPublicKeyInfo) from disk.
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	switch block.Type {
	case "PUBLIC KEY":
		keyI, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		rsaKey, ok := keyI.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PKIX key is not an RSA key")
		}
		return rsaKey, nil

	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 public key: %w", err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}
}

// PublicKeyToPEM serializes an RSA public key to PEM bytes for embedding in JWKS responses.
func PublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to PKIX: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
