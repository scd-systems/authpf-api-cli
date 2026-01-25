package cmd

import (
	"fmt"
	"regexp"
)

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("username must be 3-32 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return fmt.Errorf("username contains invalid characters")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 3 || len(password) > 128 {
		return fmt.Errorf("username must be 3-128 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(password) {
		return fmt.Errorf("username contains invalid characters")
	}
	return nil
}
