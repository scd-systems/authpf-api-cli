package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// passwordEnvVar is the environment variable a password may be handed over in when no
// terminal is in front of the tool. It is named here because a refused prompt has to name
// the way out inside its own error message.
const passwordEnvVar = "AUTHPF_API_PASSWORD"

// promptSecret reads a password from the terminal with the echo turned off. It asks once.
//
// Typing is the only way this tool accepts a password. A value on the command line sits in
// the process argument vector, which every user logged in on that host can read through
// /proc/<pid>/cmdline for as long as the process runs, and the same string then stays in
// the shell history, in the CI job log and in whatever records execve arguments.
//
// The caller gets the clear text back. readSecret is passed in so these rules can be tested
// without a terminal in front of them.
func promptSecret(w io.Writer, readSecret func() (string, error)) (string, error) {
	if _, err := fmt.Fprintf(w, "Password: "); err != nil {
		return "", err
	}

	secret, err := readSecret()
	// The line break belongs on the terminal even when the read failed halfway, or the next
	// message would start right behind the prompt. With the echo off there is no typed
	// newline for the terminal to show, so this has to be written here.
	if _, writeErr := fmt.Fprintln(w); writeErr != nil && err == nil {
		err = writeErr
	}
	if err != nil {
		return "", err
	}

	// Only emptiness is refused here. What counts as a password is the server's decision,
	// and this tool did not create the account it is being asked to log in to.
	if secret == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return secret, nil
}

// readTerminalSecret reads one hidden line from the terminal on stdin. A stdin that is not
// a terminal is refused instead of waited on: behind a pipe or in a CI job there is nobody
// who could type the answer, so that wait would never end.
func readTerminalSecret() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no terminal to type the password into, run this from a terminal or set %s", passwordEnvVar)
	}

	secret, err := term.ReadPassword(fd)
	if err != nil {
		return "", fmt.Errorf("failed to read the password: %w", err)
	}

	return string(secret), nil
}

func createPwHash(clearTextPassword string) ([]byte, error) {
	pwHash := sha256.Sum256([]byte(clearTextPassword))
	if len(pwHash) != 32 {
		return []byte{}, fmt.Errorf("something went wrong during password generation")
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
		return "", fmt.Errorf("something went wrong during password generation")
	}
	hashStr := fmt.Sprintf("%x", hash)
	return hashStr, nil
}
