package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// DecryptParameters represents the decryption input parameters.
type DecryptParameters struct {
	OurPrivateKey     string
	RemotePublicKey   string
	Base64YourNonce   string
	Base64RemoteNonce string
	Base64Data        string
	Expiry            string
}

// CipherResponse represents the response of the decryption process.
type CipherResponse struct {
	Result string
	Error  string
}

const (
	AESKeySize   = 32
	IVLength     = 12
	GCMTagLength = 16
)

// ParsePEMKey parses a PEM-encoded private or public key.
func ParsePEMKey(pemKey string, isPrivateKey bool) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if isPrivateKey {
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return privateKey, nil
	} else {
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return publicKey, nil
	}
}

// XOR performs XOR operation on two byte slices.
func XOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("lengths of the byte slices do not match")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// Decrypt performs AES-GCM decryption.
func Decrypt(privateKey interface{}, publicKey interface{}, yourNonce, remoteNonce, encodedData string) (*CipherResponse, error) {
	// Parse nonces
	yourNonceBytes, err := base64.StdEncoding.DecodeString(yourNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode your nonce: %w", err)
	}
	remoteNonceBytes, err := base64.StdEncoding.DecodeString(remoteNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode remote nonce: %w", err)
	}

	// XOR the nonces
	xoredNonce, err := XOR(yourNonceBytes, remoteNonceBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to XOR nonces: %w", err)
	}

	// Generate a shared secret (using a placeholder for shared secret generation)
	sharedSecret := GenerateSharedSecret(privateKey, publicKey)

	// Derive the AES key from the shared secret
	aesKey := DeriveAESKey(sharedSecret, xoredNonce)

	// Decode the encrypted data
	cipherData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Extract the IV from the xored nonce
	if len(xoredNonce) < IVLength {
		return nil, errors.New("invalid nonce length")
	}
	iv := xoredNonce[:IVLength]

	// Perform AES-GCM decryption
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	plainText, err := gcm.Open(nil, iv, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &CipherResponse{
		Result: base64.StdEncoding.EncodeToString(plainText),
		Error:  "",
	}, nil
}

// GenerateSharedSecret is a placeholder for shared secret generation.
func GenerateSharedSecret(privateKey interface{}, publicKey interface{}) []byte {
	// Perform key agreement here. Placeholder implementation:
	return make([]byte, AESKeySize)
}

// DeriveAESKey derives an AES key from the shared secret and nonce.
func DeriveAESKey(sharedSecret, nonce []byte) []byte {
	// Perform key derivation here. Placeholder implementation:
	return sharedSecret[:AESKeySize]
}
