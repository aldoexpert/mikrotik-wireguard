package library

import (
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes plaintext with bcrypt and base64-encodes the result
// so it can be stored as a plain JSON string.
func HashPassword(plaintext string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), 14)
	if err != nil {
		return "", fmt.Errorf("cannot hash password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hashed), nil
}

// VerifyHash checks plaintext against a base64-encoded bcrypt hash.
func VerifyHash(base64Hash string, plaintext string) (bool, error) {
	hash, err := base64.StdEncoding.DecodeString(base64Hash)
	if err != nil {
		return false, fmt.Errorf("cannot decode base64 hash: %w", err)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(plaintext))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot verify password: %w", err)
	}
	return true, nil
}
