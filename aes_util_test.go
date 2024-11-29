package main

import (
	"testing"
)

func TestSuite(t *testing.T) {
	t.Run("Encrypt/Decrypt", func(t *testing.T) {
		salt := "somesalt"
		original := "hello world"

		encrypted, err := encrypt(original, salt)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		if encrypted == "" {
			t.Fatalf("expected encrypted string, got empty")
		}

		decrypted, err := decrypt(encrypted, salt)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if decrypted != original {
			t.Errorf("expected %s, got %s", original, decrypted)
		}

		// Error cases
		_, err = decrypt("invalid_base64", salt)
		if err == nil {
			t.Error("expected error for invalid base64 but got none")
		}

		_, err = decrypt(encrypted, "")
		if err == nil {
			t.Error("expected error for empty salt but got none")
		}
	})

	t.Run("RemovePKCS7Padding", func(t *testing.T) {
		validPadded := []byte("hello\x03\x03\x03")
		invalidPadded := []byte("hello\x04\x04\x04\x04")
		blockSize := 8

		result, err := removePKCS7Padding(validPadded, blockSize)
		if err != nil {
			t.Fatalf("removePKCS7Padding failed: %v", err)
		}
		if string(result) != "hello" {
			t.Errorf("expected 'hello', got %s", string(result))
		}

		_, err = removePKCS7Padding(invalidPadded, blockSize)
		if err == nil {
			t.Error("expected error for invalid padding but got none")
		}

		_, err = removePKCS7Padding([]byte("hello"), blockSize)
		if err == nil {
			t.Error("expected error for unpadded data but got none")
		}
	})

	t.Run("EncryptValueToXor/DecryptXoredValue", func(t *testing.T) {
		key := "mysecretkey"
		original := "hello world"

		encrypted := encryptValueToXor(original, key)
		if encrypted == "" {
			t.Fatalf("expected encrypted string, got empty")
		}

		decrypted, err := decryptXoredValue(encrypted, key)
		if err != nil {
			t.Fatalf("decryptXoredValue failed: %v", err)
		}
		if decrypted != original {
			t.Errorf("expected %s, got %s", original, decrypted)
		}

		// Error cases
		_, err = decryptXoredValue("invalid_base64", key)
		if err == nil {
			t.Error("expected error for invalid base64 but got none")
		}

		_, err = decryptXoredValue("", key)
		if err == nil {
			t.Error("expected error for empty encrypted string but got none")
		}
	})

	t.Run("XOR", func(t *testing.T) {
		data := []byte("hello world")
		key := "mysecretkey"

		xored := xor(data, key)
		reversed := xor(xored, key)

		if string(reversed) != string(data) {
			t.Errorf("expected %s, got %s", string(data), string(reversed))
		}
	})
}
