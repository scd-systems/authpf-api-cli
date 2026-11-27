package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// answerReader hands back one prepared answer per call, the way a terminal would.
type answerReader struct {
	answers []string
	calls   int
	err     error
}

func (r *answerReader) read() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.calls >= len(r.answers) {
		return "", errors.New("test setup: nothing left to answer with")
	}
	answer := r.answers[r.calls]
	r.calls++

	return answer, nil
}

func TestPromptSecretAsksOnceAndReturnsWhatWasTyped(t *testing.T) {
	const typed = "C0rrect-Horse_Battery"

	var out bytes.Buffer
	reader := &answerReader{answers: []string{typed}}

	secret, err := promptSecret(&out, reader.read)
	if err != nil {
		t.Fatalf("promptSecret() returned %v, want the typed password", err)
	}
	if secret != typed {
		t.Errorf("promptSecret() = %q, want %q", secret, typed)
	}
	if reader.calls != 1 {
		t.Errorf("read %d answers, want 1 - the login is asked for once", reader.calls)
	}

	prompted := out.String()
	if !strings.Contains(prompted, "Password:") {
		t.Errorf("prompt was %q, want the password asked for", prompted)
	}
	// The whole point of a hidden read: what was typed must not come back to the screen.
	if strings.Contains(prompted, typed) {
		t.Errorf("the password was written to the terminal output: %q", prompted)
	}
}

func TestPromptSecretRefusesAnEmptyEntry(t *testing.T) {
	var out bytes.Buffer
	reader := &answerReader{answers: []string{""}}

	if _, err := promptSecret(&out, reader.read); err == nil {
		t.Fatal("an empty password was accepted")
	} else if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error was %v, want it to name the empty password", err)
	}
	if reader.calls != 1 {
		t.Errorf("read %d answers, want 1 - an empty entry is refused right there", reader.calls)
	}
}

func TestPromptSecretReportsAFailedRead(t *testing.T) {
	var out bytes.Buffer
	reader := &answerReader{err: io.ErrClosedPipe}

	if _, err := promptSecret(&out, reader.read); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("promptSecret() returned %v, want the failed read to reach the caller", err)
	}
}

// Regression: -p behind a pipe used to be impossible, and a prompt that simply waited for
// typing would hang a CI job or a script forever instead. go test hands out something that
// is not a terminal, so the refusal is reachable from here.
func TestReadTerminalSecretRefusesANonTerminalStdin(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe() failed: %v", err)
	}
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
	}()

	saved := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = saved }()

	if _, err := readTerminalSecret(); err == nil {
		t.Fatal("a stdin that is not a terminal was accepted, a prompt would now wait forever")
	} else if !strings.Contains(err.Error(), passwordEnvVar) {
		t.Errorf("error was %v, want it to name %s as the way out", err, passwordEnvVar)
	}
}

// Regression: the password flag used to be bound into viper. A bool -p would then have made
// viper answer the password with "true", which is 4 characters of allowed characters, so
// validatePassword passes it and the login is tried with the password "true".
func TestPasswordFlagIsNotBoundIntoViper(t *testing.T) {
	saved := viper.Get(VIPER_PARAM_PASSWORD)
	defer viper.Set(VIPER_PARAM_PASSWORD, saved)

	if err := authLoginCmd.Flags().Set("password", "true"); err != nil {
		t.Fatalf("setting -p failed: %v", err)
	}
	defer func() { _ = authLoginCmd.Flags().Set("password", "false") }()

	if got := viper.GetString(VIPER_PARAM_PASSWORD); got != "" {
		t.Errorf("-p reached viper as the password %q, want the flag to carry no value at all", got)
	}
}

// The property a CI job depends on: with -p given and nothing behind stdin but a pipe, the
// command fails at once. This is measured through the handler rather than through the reader
// alone, because a prompt reached anywhere else in the handler would hang the job all the same.
func TestLoginWithPasswordFlagRefusesANonTerminalAtOnce(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe() failed: %v", err)
	}
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
	}()

	savedStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = savedStdin }()

	savedUser := viper.GetString(VIPER_PARAM_USERNAME)
	savedServer := viper.GetString(VIPER_PARAM_SERVER)
	defer func() {
		viper.Set(VIPER_PARAM_USERNAME, savedUser)
		viper.Set(VIPER_PARAM_SERVER, savedServer)
	}()
	viper.Set(VIPER_PARAM_USERNAME, "alice")
	viper.Set(VIPER_PARAM_SERVER, "http://127.0.0.1:9")

	if err := authLoginCmd.Flags().Set("password", "true"); err != nil {
		t.Fatalf("setting -p failed: %v", err)
	}
	defer func() { _ = authLoginCmd.Flags().Set("password", "false") }()

	// The prompt itself would only add noise here; what is asserted is the refusal.
	authLoginCmd.SetErr(io.Discard)
	defer authLoginCmd.SetErr(nil)

	done := make(chan error, 1)
	go func() { done <- authLoginCmd.RunE(authLoginCmd, nil) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), passwordEnvVar) {
			t.Errorf("auth login -p on a pipe returned %v, want a refusal naming %s", err, passwordEnvVar)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("auth login -p is still waiting for typing after five seconds")
	}
}

// auth login must have no place to put a password: as an option value it would sit in the
// process argument vector for every local user to read, and the leftover of someone who
// still writes `-p secret` must not be printed back either.
func TestLoginHasNoPlaceForAPasswordValue(t *testing.T) {
	flag := authLoginCmd.Flags().ShorthandLookup("p")
	if flag == nil {
		t.Fatal("auth login lost its -p flag")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("-p has type %q, want bool", flag.Value.Type())
	}

	const leftover = "C0rrect-Horse_Battery"
	err := authLoginCmd.Args(authLoginCmd, []string{leftover})
	if err == nil {
		t.Fatal(`a leftover "auth login -p secret" argument was accepted`)
	}
	if strings.Contains(err.Error(), leftover) {
		t.Errorf("the refusal repeats the password: %q", err)
	}

	if err := authLoginCmd.Args(authLoginCmd, nil); err != nil {
		t.Errorf("a plain auth login without arguments was refused: %v", err)
	}
}
