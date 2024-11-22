package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/curve25519"
)

// Mock for RandomReader
type MockRandomReader struct {
	mock.Mock
}

func (m *MockRandomReader) Read(p []byte) (int, error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

// Mock for Curve25519Wrapper
type MockCurve25519Wrapper struct {
	mock.Mock
}

func (m *MockCurve25519Wrapper) X25519(privateKey, basePoint []byte) ([]byte, error) {
	args := m.Called(privateKey, basePoint)
	return args.Get(0).([]byte), args.Error(1)
}

func TestGenerateKeyMaterialWithDefault_Success(t *testing.T) {
	// Call the function with the default implementation
	keyMaterial, err := GenerateKeyMaterialWithDefault()

	// Assert that no errors occur and the key material is generated
	assert.NoError(t, err)
	assert.NotNil(t, keyMaterial)
	assert.Contains(t, keyMaterial, "cryptoAlg")
	assert.Contains(t, keyMaterial, "curve")
	assert.Contains(t, keyMaterial["DHPublicKey"], "KeyValue")
}

func TestGenerateKeyMaterial_Success(t *testing.T) {
	// Arrange
	mockReader := new(MockRandomReader)
	mockReader.On("Read", mock.Anything).Return(32, nil)

	mockCurve := new(MockCurve25519Wrapper)
	mockCurve.On("X25519", mock.Anything, curve25519.Basepoint).Return([]byte("mockedPublicKey"), nil)

	// Act
	keyMaterial, err := generateKeyMaterial(mockReader, mockCurve)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, keyMaterial)
	assert.Contains(t, keyMaterial, "cryptoAlg")
	assert.Contains(t, keyMaterial, "curve")
	assert.Contains(t, keyMaterial["DHPublicKey"], "KeyValue")
	mockReader.AssertCalled(t, "Read", mock.Anything)
}

func TestGenerateKeyMaterial_RandomReadFailure(t *testing.T) {
	// Arrange
	mockReader := new(MockRandomReader)
	mockReader.On("Read", mock.Anything).Return(0, errors.New("random read error"))

	mockCurve := new(MockCurve25519Wrapper)
	mockCurve.On("X25519", mock.Anything, curve25519.Basepoint).Return([]byte("mockedPublicKey"), nil)

	// Act
	keyMaterial, err := generateKeyMaterial(mockReader, mockCurve)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, keyMaterial)
	assert.EqualError(t, err, "error generating private key: random read error")
	mockReader.AssertCalled(t, "Read", mock.Anything)
}

func TestGenerateKeyMaterial_PublicKeyDerivationFailure(t *testing.T) {
	// Arrange
	mockReader := new(MockRandomReader)
	mockReader.On("Read", mock.Anything).Return(32, nil)

	mockCurve := new(MockCurve25519Wrapper)
	mockCurve.On("X25519", mock.Anything, curve25519.Basepoint).Return(nil, errors.New("public key derivation failed"))

	// Act
	keyMaterial, err := generateKeyMaterial(mockReader, mockCurve)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, keyMaterial)
	assert.EqualError(t, err, "error deriving public key: public key derivation failed")
	mockReader.AssertCalled(t, "Read", mock.Anything)
	mockCurve.AssertCalled(t, "X25519", mock.Anything, curve25519.Basepoint)
}

func TestGenerateKeyMaterial_NonceComputationFailure(t *testing.T) {
	// Arrange
	mockReader := new(MockRandomReader)
	mockReader.On("Read", mock.Anything).Return(32, nil)

	mockCurve := new(MockCurve25519Wrapper)
	mockCurve.On("X25519", mock.Anything, curve25519.Basepoint).Return([]byte("mockedPublicKey"), nil)
	mockCurve.On("X25519", mock.Anything, []byte("mockedPublicKey")).Return(nil, errors.New("nonce computation failed"))

	// Act
	keyMaterial, err := generateKeyMaterial(mockReader, mockCurve)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, keyMaterial)
	assert.EqualError(t, err, "error computing shared secret: nonce computation failed")
	mockReader.AssertCalled(t, "Read", mock.Anything)
	mockCurve.AssertExpectations(t)
}
