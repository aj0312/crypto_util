package main

import (
	"crypto/aes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	salt := "test-salt"
	expectedLength := 32 // SHA256 produces a 256-bit hash (32 bytes)

	key := generateKey(salt)

	if len(key) != expectedLength {
		t.Errorf("Expected key length %d, got %d", expectedLength, len(key))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	input := "hello world"
	salt := "test-salt"

	encrypted, err := encrypt(input, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := decrypt(encrypted, salt)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != input {
		t.Errorf("Expected decrypted value '%s', got '%s'", input, decrypted)
	}
}

func TestEncryptDecryptInvalidPadding(t *testing.T) {
	input := "hello world"
	salt := "test-salt"

	encrypted, err := encrypt(input, salt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the padding in the ciphertext
	decodedCiphertext, _ := base64.StdEncoding.DecodeString(encrypted)
	decodedCiphertext[len(decodedCiphertext)-1] = byte(aes.BlockSize + 1) // Invalid padding
	corruptedCiphertext := base64.StdEncoding.EncodeToString(decodedCiphertext)

	_, err = decrypt(corruptedCiphertext, salt)
	if err == nil || !strings.Contains(err.Error(), "invalid padding") {
		t.Errorf("Expected 'invalid padding' error, got %v", err)
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	// Ensure the input is valid Base64 but too short to contain an IV
	encrypted := base64.StdEncoding.EncodeToString([]byte("short"))
	salt := "test-salt"

	_, err := decrypt(encrypted, salt)
	if err == nil || !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("Expected 'ciphertext too short' error, got %v", err)
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	encrypted := "invalid-base64$"
	salt := "test-salt"

	_, err := decrypt(encrypted, salt)
	if err == nil || !strings.Contains(err.Error(), "illegal base64 data") {
		t.Errorf("Expected 'illegal base64 data' error, got %v", err)
	}
}

func TestEncryptValueToXorAndDecryptXoredValue(t *testing.T) {
	input := "hello world"
	key := "test-key"

	encrypted, err := encryptValueToXor(input, key)
	if err != nil {
		t.Fatalf("EncryptValueToXor failed: %v", err)
	}

	decrypted, err := decryptXoredValue(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptXoredValue failed: %v", err)
	}

	if decrypted != input {
		t.Errorf("Expected decrypted value '%s', got '%s'", input, decrypted)
	}
}

func TestEncryptValueToXorInvalidBase64(t *testing.T) {
	invalidBase64 := "invalid-base64$"
	key := "test-key"

	_, err := decryptXoredValue(invalidBase64, key)
	if err == nil || !strings.Contains(err.Error(), "illegal base64 data") {
		t.Errorf("Expected 'illegal base64 data' error, got %v", err)
	}
}

func TestXor(t *testing.T) {
	data := []byte("hello")
	key := "key"

	xored := xor(data, key)
	unxored := xor(xored, key)

	if string(unxored) != string(data) {
		t.Errorf("Expected unxored value '%s', got '%s'", string(data), string(unxored))
	}
}
