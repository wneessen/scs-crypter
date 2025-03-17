// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package scscrypter

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	testKey256 = []byte{
		0xbf, 0x8b, 0x34, 0xf7, 0x7d, 0x5c, 0x44, 0x7e, 0xbf, 0x56, 0x16, 0x34, 0x27, 0x97, 0x60, 0x27,
		0xfd, 0x30, 0xa6, 0xa2, 0x40, 0x76, 0xd4, 0x53, 0xec, 0x58, 0xe3, 0xb8, 0x60, 0xd1, 0x10, 0xdd,
	}
	testKey128 = []byte{
		0xd3, 0xfc, 0xe3, 0x8c, 0xa3, 0xc8, 0xfd, 0x44, 0x37, 0x60, 0x65, 0x7f, 0x85, 0x9d, 0xba, 0x33,
	}
)

func TestEncryptor_New(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		newFunc func(key []byte) (Encrypter, error)
	}{
		{"AES-256-GCM", testKey256, NewAESGCM},
		{"AES-128-GCM", testKey128, NewAESGCM},
		{"ChaCha20-Poly1305", testKey256, NewChaCha20Poly1305},
		{"XChaCha20-Poly1305", testKey256, NewXChaCha20Poly1305},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			if _, err = encrypter.Encode(time.Now(), map[string]interface{}{}); err != nil {
				t.Errorf("failed to encode data: %s", err)
			}
		})
	}
	t.Run("Nil cipher", func(t *testing.T) {
		encryptor := New(nil)
		if encryptor.cipher != nil {
			t.Fatalf("expected cipher to be nil")
		}
		_, err := encryptor.Encode(time.Now(), map[string]interface{}{})
		if err == nil {
			t.Fatalf("encryptor with nil cipher should fail")
		}
		if !errors.Is(err, ErrNoCipher) {
			t.Errorf("expected ErrNoCipher, got %s", err)
		}
	})
}

func TestNewAESGCM(t *testing.T) {
	t.Run("Invalid key length", func(t *testing.T) {
		_, err := NewAESGCM([]byte{0x00})
		if err == nil {
			t.Fatalf("expected AES-GCM creation to fail with invalid key length")
		}
	})
}

func TestNewChaCha20Poly1305(t *testing.T) {
	t.Run("Invalid key length", func(t *testing.T) {
		_, err := NewChaCha20Poly1305([]byte{0x00})
		if err == nil {
			t.Fatalf("expected ChaCha20-Poly1305 creation to fail with invalid key length")
		}
	})
}

func TestNewXChaCha20Poly1305(t *testing.T) {
	t.Run("Invalid key length", func(t *testing.T) {
		_, err := NewXChaCha20Poly1305([]byte{0x00})
		if err == nil {
			t.Fatalf("expected XChaCha20-Poly1305 creation to fail with invalid key length")
		}
	})
}

func TestEncrypter_Encode(t *testing.T) {
	data := map[string]interface{}{
		"string": "test",
		"int":    42,
		"bool":   true,
		"uint":   666,
		"bytes":  []byte("Bytes"),
	}
	tests := []struct {
		name    string
		key     []byte
		newFunc func(key []byte) (Encrypter, error)
	}{
		{"AES-256-GCM", testKey256, NewAESGCM},
		{"AES-128-GCM", testKey128, NewAESGCM},
		{"ChaCha20-Poly1305", testKey256, NewChaCha20Poly1305},
		{"XChaCha20-Poly1305", testKey256, NewXChaCha20Poly1305},
	}
	now := time.Now()
	for _, tt := range tests {
		t.Run(tt.name+" succeeds", func(t *testing.T) {
			encrypter, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			ciphertext, err := encrypter.Encode(now, data)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			plaintime, plaindata, err := encrypter.Decode(ciphertext)
			if err != nil {
				t.Fatalf("decryption failed: %s", err)
			}
			if !plaintime.Equal(now) {
				t.Errorf("expected plaintime to be %s, got %s", now, plaintime)
			}
			if value, ok := plaindata["string"]; !ok || value != data["string"] {
				t.Errorf("expected decrypted string to be %s, got %s", data["string"], value)
			}
			if value, ok := plaindata["int"]; !ok || value != data["int"] {
				t.Errorf("expected decrypted int to be %d, got %d", data["int"], value)
			}
			if value, ok := plaindata["uint"]; !ok || value != data["uint"] {
				t.Errorf("expected decrypted uint to be %d, got %d", data["uint"], value)
			}
			if value, ok := plaindata["bytes"]; !ok || !bytes.Equal(value.([]byte), data["bytes"].([]byte)) {
				t.Errorf("expected decrypted bytes to be %x, got %x", data["bytes"], value)
			}
		})
		t.Run(tt.name+" fails with unregistered gob type", func(t *testing.T) {
			unregistered := map[string]interface{}{
				"unregistered": map[string]string{"foo": "bar"},
			}
			encrypter, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			_, err = encrypter.Encode(now, unregistered)
			if err == nil {
				t.Errorf("expected encryption to fail with unregistered gob type")
			}
		})
	}
}

func TestEncrypter_Decode(t *testing.T) {
	data := map[string]interface{}{
		"string": "test",
		"int":    42,
		"bool":   true,
		"uint":   666,
		"bytes":  []byte("Bytes"),
	}
	tests := []struct {
		name    string
		key     []byte
		newFunc func(key []byte) (Encrypter, error)
	}{
		{"AES-256-GCM", testKey256, NewAESGCM},
		{"AES-128-GCM", testKey128, NewAESGCM},
		{"ChaCha20-Poly1305", testKey256, NewChaCha20Poly1305},
		{"XChaCha20-Poly1305", testKey256, NewXChaCha20Poly1305},
	}
	for _, tt := range tests {
		t.Run(tt.name+" fails with incomplete data", func(t *testing.T) {
			encrypter, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			ciphertext, err := encrypter.Encode(time.Now(), data)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			_, _, err = encrypter.Decode(ciphertext[:len(ciphertext)-1])
			if err == nil {
				t.Errorf("expected decryption to fail with incomplete data")
			}
		})
		t.Run(tt.name+" fails with incompatible gob type", func(t *testing.T) {
			encrypter, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			ciphertext, err := encrypter.encrypt([]byte("foobar"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			_, _, err = encrypter.Decode(ciphertext)
			if err == nil {
				t.Errorf("expected decryption to fail with incompatible gob type")
			}
		})
	}
}

func TestEncrypter_encrypt(t *testing.T) {
	tests := []struct {
		name                string
		key                 []byte
		newFunc             func(key []byte) (Encrypter, error)
		skipRandReaderCheck bool
	}{
		{"AES-256-GCM", testKey256, NewAESGCM, true},
		{"AES-128-GCM", testKey128, NewAESGCM, true},
		{"ChaCha20-Poly1305", testKey256, NewChaCha20Poly1305, false},
		{"XChaCha20-Poly1305", testKey256, NewXChaCha20Poly1305, false},
	}
	for _, tt := range tests {
		t.Run("encrypt fails reading random nonce", func(t *testing.T) {
			if tt.skipRandReaderCheck {
				t.SkipNow()
			}
			encryptor, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			defaultRandReader := rand.Reader
			t.Cleanup(func() { rand.Reader = defaultRandReader })
			rand.Reader = &failReader{}
			_, err = encryptor.encrypt([]byte("test data"))
			if err == nil {
				t.Fatalf("expected encryption to fail")
			}
			if !strings.Contains(err.Error(), "intentionally failed to read") {
				t.Errorf("expected error to be 'intentionally failed to read', got '%s'", err.Error())
			}
		})
	}
}

func TestEncrypter_decrypt(t *testing.T) {
	tests := []struct {
		name           string
		key            []byte
		newFunc        func(key []byte) (Encrypter, error)
		skipShortCheck bool
	}{
		{"AES-256-GCM", testKey256, NewAESGCM, true},
		{"AES-128-GCM", testKey128, NewAESGCM, true},
		{"ChaCha20-Poly1305", testKey256, NewChaCha20Poly1305, false},
		{"XChaCha20-Poly1305", testKey256, NewXChaCha20Poly1305, false},
	}
	for _, tt := range tests {
		t.Run(tt.name+" fails with too short data", func(t *testing.T) {
			encryptor, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			_, err = encryptor.decrypt([]byte{0x01})
			if err == nil {
				t.Errorf("expected decryption to fail with too short data")
			}
			if !tt.skipShortCheck && !errors.Is(err, ErrCiphertextTooShort) {
				t.Errorf("expected ErrCiphertextTooShort, got %s", err)
			}
		})
		t.Run(tt.name+" fails with nil data", func(t *testing.T) {
			encryptor, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			_, err = encryptor.decrypt(nil)
			if err == nil {
				t.Errorf("expected decryption to fail with nil data")
			}
		})
		t.Run(tt.name+" fails with nil cipher", func(t *testing.T) {
			encryptor, err := tt.newFunc(tt.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %s", err)
			}
			encryptor.cipher = nil
			_, err = encryptor.decrypt([]byte{0x01})
			if err == nil {
				t.Errorf("expected decryption to fail with nil cipher")
			}
			if !errors.Is(err, ErrNoCipher) {
				t.Errorf("expected ErrNoCipher, got %s", err)
			}
		})
	}
}

// failReader is a type that intentionally fails. It satisfies the io.Reader interface
type failReader struct{}

// Read implements the io.Reader interface for the failReader type
func (r *failReader) Read([]byte) (n int, err error) {
	return 0, errors.New("intentionally failed to read")
}
