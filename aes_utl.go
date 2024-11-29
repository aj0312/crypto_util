package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
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
func decrypt(encrypted, salt string) (string, error) {
	key := generateKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Create a new CBC mode decrypter
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	padding := int(ciphertext[len(ciphertext)-1])
	if padding < 1 || padding > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}
	plaintext := ciphertext[:len(ciphertext)-padding]

	return string(plaintext), nil
}

// xor function: Applies XOR operation between input bytes and key bytes
func xor(data []byte, key string) []byte {
	keyBytes := []byte(key)
	out := make([]byte, len(data))

	for i := range data {
		out[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}

	return out
}

// EncryptValueToXor: Encodes the input string using XOR and Base64
func encryptValueToXor(input, key string) (string, error) {
	xoredBytes := xor([]byte(input), key)
	encoded := base64.StdEncoding.EncodeToString(xoredBytes)
	return encoded, nil
}

// DecryptXoredValue: Decodes the Base64 string and applies XOR to retrieve the original value
func decryptXoredValue(encoded, key string) (string, error) {
	xoredBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	decodedBytes := xor(xoredBytes, key)
	return string(decodedBytes), nil
}
