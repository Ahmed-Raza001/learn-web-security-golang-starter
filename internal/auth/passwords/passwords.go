package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
    MaxLength       = 128
    memoryKiB       = 19 * 1024
    iterations      = 2
    parallelism     = 1
    derivedKeyLength = 32
)

func Hash(password string) (string, error) {
    if utf8.RuneCountInString(password) > MaxLength {
        return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
    }

    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    derivedKey := argon2.IDKey(
        []byte(password),
        salt,
        iterations,
        memoryKiB,
        parallelism,
        derivedKeyLength,
    )

    return encodeArgon2idHash(argon2idHash{
        version:     argon2.Version,
        memoryKiB:   memoryKiB,
        iterations:  iterations,
        parallelism: parallelism,
        salt:        salt,
        derivedKey:  derivedKey,
    }), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	// Verify legacy SHA-256 hashes.
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	// Parse Argon2id hash.
	hash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}

	// Ensure the Argon2 version is supported.
	if hash.version != argon2.Version {
		return false
	}

	// Derive key using stored parameters and salt.
	candidateKey := argon2.IDKey(
		[]byte(password),
		hash.salt,
		hash.iterations,
		hash.memoryKiB,
		hash.parallelism,
		uint32(len(hash.derivedKey)),
	)

	// Compare derived keys in constant time.
	return subtle.ConstantTimeCompare(candidateKey, hash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
    // Legacy SHA-256 hashes need upgrading.
    if _, ok := decodeLegacyHash(encodedHash); ok {
        return true
    }

    // Parse Argon2id hash.
    hash, ok := parseArgon2idHash(encodedHash)
    if !ok {
        return false
    }

    // Check whether the stored parameters match current policy.
    return hash.version != argon2.Version ||
        hash.memoryKiB != memoryKiB ||
        hash.iterations != iterations ||
        hash.parallelism != parallelism ||
        len(hash.derivedKey) != derivedKeyLength
}
