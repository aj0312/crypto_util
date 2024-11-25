package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func decodePEMKey(pemKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("invalid PEM format")
	}
	return block.Bytes, nil
}

func generateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	// X25519 performs the scalar multiplication
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	return sharedSecret, nil
}

func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("inputs for XOR must have the same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func deriveKey(sharedSecret, salt []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, nil)
	key := make([]byte, 32) // AES-256 key size
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptAESGCM(key, nonce, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Encrypt(
	base64RemoteNonce, base64YourNonce, base64PrivateKey, base64RemotePublicKey, plaintext string,
) (string, error) {
	// Decode inputs
	remoteNonce, err := base64.StdEncoding.DecodeString(base64RemoteNonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode remote nonce: %v", err)
	}
	yourNonce, err := base64.StdEncoding.DecodeString(base64YourNonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode your nonce: %v", err)
	}
	privateKeyPEM, err := decodePEMKey(base64PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}
	remotePublicKeyPEM, err := decodePEMKey(base64RemotePublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode remote public key: %v", err)
	}

	// Compute shared secret
	sharedSecret, err := generateSharedSecret(privateKeyPEM, remotePublicKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to generate shared secret: %v", err)
	}

	// XOR the nonces
	xoredNonce, err := xorBytes(remoteNonce, yourNonce)
	if err != nil {
		return "", fmt.Errorf("failed to XOR nonces: %v", err)
	}

	// Derive session key
	sessionKey, err := deriveKey(sharedSecret, xoredNonce[:20])
	if err != nil {
		return "", fmt.Errorf("failed to derive session key: %v", err)
	}

	// Use the last 12 bytes of xoredNonce as the IV
	iv := xoredNonce[len(xoredNonce)-12:]

	// Encrypt data
	encrypted, err := encryptAESGCM(sessionKey, iv, []byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}
	return encrypted, nil
}
