package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/xdg-go/pbkdf2"
)

// Generate a key from the given salt using SHA256
func generateKey(salt string) []byte {
	hash := sha256.Sum256([]byte(salt))
	return hash[:]
}

// Encrypt function
func encrypt(strToEncrypt, salt string) (string, error) {
	secretKey := "ac12ghd75kf75r"
	iv := make([]byte, 16) // 16 bytes of zeros

	// Key derivation using PBKDF2 with HMAC-SHA256
	password := []byte(secretKey)
	saltBytes := []byte(salt)
	key := pbkdf2.Key(password, saltBytes, 65536, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Pad the plaintext using PKCS7
	plaintext := []byte(strToEncrypt)
	blockSize := block.BlockSize()
	padding := blockSize - len(plaintext)%blockSize
	paddedData := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	// Encrypt the data
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	// Encode to URL-safe Base64
	encData := base64.URLEncoding.EncodeToString(ciphertext)

	return encData, nil
}

// Decrypt function
func decrypt(encryptedStr, salt string) (string, error) {
	secretKey := "ac12ghd75kf75r"
	iv := make([]byte, 16) // 16 bytes of zeros

	// Key derivation using PBKDF2 with HMAC-SHA256
	password := []byte(secretKey)
	saltBytes := []byte(salt)
	key := pbkdf2.Key(password, saltBytes, 65536, 32, sha256.New)

	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = removePKCS7Padding(plaintext, block.BlockSize())
	if err != nil {
		return "", fmt.Errorf("failed to remove padding: %w", err)
	}

	return string(plaintext), nil
}

// Remove PKCS7 padding
func removePKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}

	// Get the last byte value as padding length
	padding := int(data[length-1])
	if padding > blockSize || padding == 0 {
		return nil, errors.New("invalid padding size")
	}

	// Check if padding bytes are all the same
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding bytes")
		}
	}

	return data[:length-padding], nil
}

// xor function: Applies XOR operation between input bytes and key bytes
func xor(data []byte, key string) []byte {
	keyBytes := []byte(key)
	output := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		output[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}
	return output

}

// EncryptValueToXor: Encodes the input string using XOR and Base64
func encryptValueToXor(value string, key string) string {
	xoredBytes := xor([]byte(value), key)
	encoded := base64.StdEncoding.EncodeToString(xoredBytes)
	return encoded
}

// DecryptXoredValue: Decodes the Base64 string and applies XOR to retrieve the original value
func decryptXoredValue(xoredValue, key string) (string, error) {
	xoredBytes, err := base64.StdEncoding.DecodeString(xoredValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	originalBytes := xor(xoredBytes, key)
	return string(originalBytes), nil
}
