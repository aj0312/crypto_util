package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func getPEMDecodedStream(pemEncodedKey string, isPrivateKey bool) ([]byte, error) {
	// Remove headers and footers, normalize content
	encodedKey := strings.ReplaceAll(pemEncodedKey, "-----BEGIN PRIVATE KEY-----", "")
	encodedKey = strings.ReplaceAll(encodedKey, "-----END PRIVATE KEY-----", "")
	encodedKey = strings.ReplaceAll(encodedKey, "-----BEGIN PUBLIC KEY-----", "")
	encodedKey = strings.ReplaceAll(encodedKey, "-----END PUBLIC KEY-----", "")
	encodedKey = strings.ReplaceAll(encodedKey, "\r", "")
	encodedKey = strings.ReplaceAll(encodedKey, "\n", "")
	encodedKey = strings.ReplaceAll(encodedKey, "\\r", "")
	encodedKey = strings.ReplaceAll(encodedKey, "\\n", "")
	encodedKey = strings.TrimSpace(encodedKey)

	// Base64 decode the key
	rawKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %v", err)
	}

	if isPrivateKey {
		// Check if the private key is X25519 (32 bytes)
		if len(rawKey) != 48 {
			return nil, errors.New("invalid private key size; expected 32 bytes for Curve25519")
		}
		return rawKey, nil
	}

	// Parse the public key (X25519 requires a valid public key of 32 bytes)
	publicKey, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	pubKey, ok := publicKey.(*ed25519.PublicKey)
	if !ok || len(*pubKey) != 32 {
		return nil, errors.New("invalid public key type or size; expected X25519 public key")
	}

	return rawKey, nil
}

func GenerateSharedNonce(privateKeyPEM, publicKeyPEM string) ([]byte, error) {
	privateKey, err := getPEMDecodedStream(privateKeyPEM, true)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %v", err)
	}

	publicKey, err := getPEMDecodedStream(publicKeyPEM, false)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %v", err)
	}

	// Perform X25519 shared secret calculation using private and public keys
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v", err)
	}

	return sharedSecret, nil
}
