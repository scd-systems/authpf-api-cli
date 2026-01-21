package cmd

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func createPwHash(clearTextPassword string) ([]byte, error) {
	pwHash := sha256.Sum256([]byte(clearTextPassword))
	if len(pwHash) != 32 {
		return []byte{}, fmt.Errorf("Something went wrong during password generation")
	}
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword(pwHash[:], bcrypt.DefaultCost)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to hash password: %w", err)
	}
	return hashedPasswordBytes, nil
}

func createSha256(text string) (string, error) {
	hash := sha256.Sum256([]byte(text))
	if len(hash) != 32 {
		return "", fmt.Errorf("Something went wrong during password generation")
	}
	hashStr := fmt.Sprintf("%x", hash)
	return hashStr, nil
}
