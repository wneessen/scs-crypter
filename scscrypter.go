// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package scscrypter implements the Codec interface of Alex Edward's SCS Session Management
// package. It encrypts session data using an authenticated encryption with additional data (AEAD)
// cipher like AES-GCM or ChaCha20-Poly1305.
package scscrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrNoCipher is an error indicating that a cipher value is missing or nil when it is required.
	ErrNoCipher = errors.New("cipher is nil")

	// ErrCiphertextTooShort indicates that the provided ciphertext is shorter than the required length.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// Encrypter provides encryption and decryption capabilities using an
// authenticated encryption with additional data (AEAD) cipher. This struct
// enables secure encryption with integrity verification, ensuring that the
// encrypted data has not been tampered with.
//
// Fields:
//   - cipher (cipher.AEAD): An AEAD cipher used to perform the encryption
//     and decryption. The cipher must be initialized before use, and it provides
//     both confidentiality and authenticity for the data.
//
// Usage:
// The Encrypter struct is designed for encrypting sensitive data that needs
// to be securely stored. It can be used in conjunction with additional functions
// that handle encoding and decoding, making it suitable for complex data structures.
type Encrypter struct {
	cipher cipher.AEAD
}

// New creates a new Encrypter instance using the provided AEAD cipher for
// encryption and decryption. This function allows initializing an Encrypter
// with a specific AEAD cipher, enabling secure and authenticated encryption
// capabilities.
//
// Parameters:
//   - aead cipher.AEAD: The AEAD cipher used for encryption and decryption.
//     This cipher must be properly initialized before calling New.
//
// Returns:
//   - Encrypter: An Encrypter instance configured with the given AEAD cipher,
//     ready to perform encryption and decryption operations.
func New(aead cipher.AEAD) Encrypter {
	return Encrypter{
		cipher: aead,
	}
}

// NewAESGCM creates a new Encrypter instance using AES-GCM mode with the
// provided key. This function initializes an AES cipher, derives an AEAD
// instance using GCM mode, and returns an Encrypter configured for secure
// encryption and decryption.
//
// Parameters:
//   - key []byte: The encryption key used to initialize the AES cipher.
//     The key must be a valid length for AES (e.g., 16, 24, or 32 bytes).
//
// Returns:
//   - Encrypter: An Encrypter instance configured with AES-GCM for encryption
//     and decryption operations.
//   - error: An error if the cipher creation or AEAD initialization fails.
func NewAESGCM(key []byte) (Encrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return Encrypter{}, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return Encrypter{}, fmt.Errorf("failed to create AES-GCM AEAD: %w", err)
	}
	return New(aead), nil
}

// NewChaCha20Poly1305 creates a new Encrypter instance using the ChaCha20-Poly1305
// AEAD cipher with the provided key. This function initializes a ChaCha20-Poly1305
// AEAD instance and returns an Encrypter configured for secure encryption and
// decryption.
//
// Parameters:
//   - key []byte: The encryption key used to initialize the ChaCha20-Poly1305 cipher.
//     The key must be exactly 32 bytes in length.
//
// Returns:
//   - Encrypter: An Encrypter instance configured with ChaCha20-Poly1305 for encryption
//     and decryption operations.
//   - error: An error if the AEAD initialization fails.
func NewChaCha20Poly1305(key []byte) (Encrypter, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Encrypter{}, fmt.Errorf("failed to create ChaCha20-Poly1305 AEAD: %w", err)
	}
	return New(aead), nil
}

// NewXChaCha20Poly1305 creates a new Encrypter instance using the XChaCha20-Poly1305
// AEAD cipher with the provided key. This function initializes an XChaCha20-Poly1305
// AEAD instance and returns an Encrypter configured for secure encryption and
// decryption.
//
// Parameters:
//   - key []byte: The encryption key used to initialize the XChaCha20-Poly1305 cipher.
//     The key must be exactly 32 bytes in length.
//
// Returns:
//   - Encrypter: An Encrypter instance configured with XChaCha20-Poly1305 for encryption
//     and decryption operations.
//   - error: An error if the AEAD initialization fails.
func NewXChaCha20Poly1305(key []byte) (Encrypter, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Encrypter{}, fmt.Errorf("failed to create ChaCha20-Poly1305 AEAD: %w", err)
	}
	return New(aead), nil
}

// Encode serializes and encrypts session data, ensuring secure storage.
//
// Parameters:
//   - deadline (time.Time): The expiration time of the session data.
//   - values (map[string]interface{}): The session values to be encoded and encrypted.
//
// Returns:
//   - []byte: The encrypted session data.
//   - error: An error if encoding or encryption fails.
//
// The function first serializes the input data using gob encoding, then encrypts it using
// the underlying iocrypter encryption mechanism.
func (e Encrypter) Encode(deadline time.Time, values map[string]interface{}) ([]byte, error) {
	aux := &struct {
		Deadline time.Time
		Values   map[string]interface{}
	}{
		Deadline: deadline,
		Values:   values,
	}

	buffer := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buffer).Encode(aux); err != nil {
		return nil, fmt.Errorf("failed to encode session data: %w", err)
	}

	return e.encrypt(buffer.Bytes())
}

// Decode decrypts and deserializes session data, restoring the original values.
//
// Parameters:
//   - ciphertext ([]byte): The encrypted session data to be decrypted and decoded.
//
// Returns:
//   - time.Time: The original session expiration time.
//   - map[string]interface{}: The restored session values.
//   - error: An error if decryption or decoding fails.
//
// The function decrypts the given ciphertext using iocrypter and deserializes it back
// into its structured session representation.
func (e Encrypter) Decode(ciphertext []byte) (time.Time, map[string]interface{}, error) {
	aux := &struct {
		Deadline time.Time
		Values   map[string]interface{}
	}{}

	data, err := e.decrypt(ciphertext)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}
	decrypter := bytes.NewReader(data)
	if err = gob.NewDecoder(decrypter).Decode(&aux); err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to decode session data: %w", err)
	}

	return aux.Deadline, aux.Values, nil
}

// encrypt is the underlying encryption method
func (e Encrypter) encrypt(data []byte) ([]byte, error) {
	if e.cipher == nil {
		return nil, ErrNoCipher
	}
	nonce := make([]byte, e.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random iv: %w", err)
	}
	cipherText := e.cipher.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// decrypt is the underlying decyption method
func (e Encrypter) decrypt(data []byte) ([]byte, error) {
	if e.cipher == nil {
		return nil, ErrNoCipher
	}
	if len(data) < e.cipher.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, ciphertext := data[:e.cipher.NonceSize()], data[e.cipher.NonceSize():]
	return e.cipher.Open(nil, nonce, ciphertext, nil)
}
