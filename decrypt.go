package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

func decryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func Decrypt(
	base64RemoteNonce, base64YourNonce, encryptedData, base64PrivateKey, base64RemotePublicKey, expiry string,
) (string, error) {
	// Parse expiry
	expiryTime, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to parse expiry time: %v", err)
	}

	// Check if the encrypted data has expired
	if time.Now().After(expiryTime) {
		return "", errors.New("encrypted data has expired")
	}

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

	// Decode the encrypted data
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// Decrypt the data
	plaintext, err := decryptAESGCM(sessionKey, iv, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return string(plaintext), nil
}
