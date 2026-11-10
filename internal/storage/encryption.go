package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, nil)

	tagSize := aead.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(payload.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	if len(payload.AuthTag) != aead.Overhead() {
		return nil, fmt.Errorf("invalid authentication tag size")
	}

	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)

	plaintext, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return plaintext, nil
}