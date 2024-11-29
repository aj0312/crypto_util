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

	t.Run("RemovePKCS7Padding/InvalidPaddingBytes", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // Invalid padding
		blockSize := 8
		_, err := removePKCS7Padding(data, blockSize)
		if err == nil {
			t.Error("expected error due to invalid padding bytes but got none")
		}
	})

	t.Run("Encrypt/AESNewCipherError", func(t *testing.T) {
		// Simulate an invalid salt that leads to invalid key
		longSalt := string(make([]byte, 1000000)) // Large salt may produce an invalid key
		_, err := encrypt("testdata", longSalt)
		if err == nil || err.Error() != "failed to create AES cipher: cipher: message authentication code mismatch" {
			t.Errorf("expected AES cipher creation error but got: %v", err)
		}
	})
	t.Run("Decrypt/AESNewCipherError", func(t *testing.T) {
		// Simulate an invalid salt that produces an invalid key
		longSalt := string(make([]byte, 1000000)) // Large salt may produce an invalid key
		_, err := decrypt("invalidEncryptedData", longSalt)
		if err == nil || err.Error() != "failed to create AES cipher: cipher: message authentication code mismatch" {
			t.Errorf("expected AES cipher creation error but got: %v", err)
		}
	})

	t.Run("RemovePKCS7Padding/InvalidPaddingBytes", func(t *testing.T) {
		// Create invalid padding: last byte indicates padding length, but preceding bytes differ
		data := []byte{0x10, 0x10, 0x10, 0x01} // Incorrect padding sequence
		_, err := removePKCS7Padding(data, 4)
		if err == nil || err.Error() != "invalid padding bytes" {
			t.Errorf("expected invalid padding bytes error but got: %v", err)
		}
	})

}
