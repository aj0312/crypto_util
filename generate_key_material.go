package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)


func PrintECDH() {
	keyMaterial, err := GenerateKeyMaterial()
	if err != nil {
		fmt.Printf("Error generating KeyMaterial: %v\n", err)
		return
	}

	// Print the generated KeyMaterial as JSON
	fmt.Printf("KeyMaterial: %+v\n", keyMaterial)
}

// computeSharedSecret generates the shared secret using a private key and a peer's public key
func computeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

// GenerateKeyMaterial generates the `KeyMaterial` field required for the API request
func GenerateKeyMaterial() (map[string]interface{}, error) {
	// Generate a private key (32 bytes)
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	// Derive the public key using Curve25519
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("error deriving public key: %v", err)
	}

	// Encode the public key in base64 for the request
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)

	nonce, err := computeSharedSecret(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("error computing shared secret: %v", err)
	}

	// Encode the nonce in base64 for the request
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)

	// Set an expiry date for the public key (example: 24 hours from now)
	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	// Build the KeyMaterial map
	keyMaterial := map[string]interface{}{
		"cryptoAlg": "ECDH",
		"curve":     "X25519",
		"params":    "",
		"DHPublicKey": map[string]string{
			"expiry":     expiry,
			"Parameters": "",
			"KeyValue":   fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", encodedPublicKey),
		},
		"Nonce": encodedNonce,
	}
	encodedPrivateKey := base64.StdEncoding.EncodeToString(privateKey)
	prKey := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n", encodedPrivateKey)
	fmt.Printf("Private Key %v\n", prKey)

	return keyMaterial, nil
}
