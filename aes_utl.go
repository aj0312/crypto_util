package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Generate a key from the given salt using SHA256
func generateKey(salt string) []byte {
	hash := sha256.Sum256([]byte(salt))
	return hash[:]
}

// Encrypt function
func encrypt(input, salt string) (string, error) {
	key := generateKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(input)

	// Padding to ensure plaintext length is a multiple of the block size
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	paddedText := append(plaintext, byte(padding))
	for i := 1; i < padding; i++ {
		paddedText = append(paddedText, byte(padding))
	}

	ciphertext := make([]byte, aes.BlockSize+len(paddedText))
	iv := ciphertext[:aes.BlockSize] // Initialization vector

	// Create a new CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	// Encode to base64 for easier representation
	return base64.StdEncoding.EncodeToString(ciphertext), nil
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
