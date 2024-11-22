package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// RandomReader defines the interface for a random number generator
type RandomReader interface {
	Read(p []byte) (n int, err error)
}

// DefaultRandomReader uses the standard crypto/rand package
type DefaultRandomReader struct{}

func (d *DefaultRandomReader) Read(p []byte) (int, error) {
	return rand.Read(p)
}

// Curve25519Wrapper defines an interface for the X25519 function
type Curve25519Wrapper interface {
	X25519(privateKey, basePoint []byte) ([]byte, error)
}

// RealCurve25519Wrapper provides the real implementation of the Curve25519 X25519 function
type RealCurve25519Wrapper struct{}

// X25519 calls the actual curve25519.X25519 function
func (w *RealCurve25519Wrapper) X25519(privateKey, basePoint []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, basePoint)
}

// GenerateKeyMaterialWithDefault is the main entry point that uses the default random reader
func GenerateKeyMaterialWithDefault() (map[string]interface{}, error) {
	return generateKeyMaterial(&DefaultRandomReader{}, &RealCurve25519Wrapper{})
}

// GenerateKeyMaterialWithWrapper generates the key material using a custom Curve25519 wrapper
func generateKeyMaterial(randomReader RandomReader, curveWrapper Curve25519Wrapper) (map[string]interface{}, error) {
	// Generate a private key (32 bytes)
	privateKey := make([]byte, 32)
	_, err := randomReader.Read(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	// Derive the public key using the wrapper
	publicKey, err := curveWrapper.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("error deriving public key: %v", err)
	}

	// Encode the public key in base64
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)

	// Compute the nonce (shared secret)
	nonce, err := curveWrapper.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("error computing shared secret: %v", err)
	}

	// Encode the nonce in base64
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)

	// Set an expiry date for the public key
	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	// Build the KeyMaterial map
	return map[string]interface{}{
		"cryptoAlg": "ECDH",
		"curve":     "X25519",
		"params":    "",
		"DHPublicKey": map[string]string{
			"expiry":     expiry,
			"Parameters": "",
			"KeyValue":   fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", encodedPublicKey),
		},
		"Nonce": encodedNonce,
	}, nil
}
