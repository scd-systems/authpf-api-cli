package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// Regression: the server accepted the token, but the client clock runs about a week ahead.
// Expiry must then still be counted on the server clock, never on the client clock.
func TestTokenValidationRemainingUsesServerClock(t *testing.T) {
	serverTime := time.Now().UTC().Add(-8 * 24 * time.Hour)
	expiresAt := serverTime.Add(time.Hour)

	v := tokenValidation{valid: true, expiresAt: expiresAt, serverTime: serverTime}

	if remaining := v.remaining(); remaining < 59*time.Minute || remaining > 61*time.Minute {
		t.Errorf("remaining() = %v, want about 1h measured on the server clock", remaining)
	}

	if local := time.Until(expiresAt); local > 0 {
		t.Fatalf("test setup is broken, the client clock is expected to be past the expiry, got %v", local)
	}
}

func TestTokenValidationRemainingWithoutServerClock(t *testing.T) {
	v := tokenValidation{valid: true, expiresAt: time.Now().Add(30 * time.Minute)}

	if remaining := v.remaining(); remaining < 29*time.Minute || remaining > 31*time.Minute {
		t.Errorf("remaining() = %v, want about 30m from the local clock as last resort", remaining)
	}
}

func TestClockSkewWarning(t *testing.T) {
	tests := []struct {
		name       string
		serverTime time.Time
		wantEmpty  bool
		wantSub    string
	}{
		{name: "server revealed no clock", serverTime: time.Time{}, wantEmpty: true},
		{name: "skew within tolerance", serverTime: time.Now().UTC().Add(-90 * time.Second), wantEmpty: true},
		{name: "client ahead", serverTime: time.Now().UTC().Add(-8 * 24 * time.Hour), wantSub: "AHEAD of server clock"},
		{name: "client behind", serverTime: time.Now().UTC().Add(3 * time.Hour), wantSub: "BEHIND server clock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := clockSkewWarning(tt.serverTime)

			if tt.wantEmpty {
				if warning != "" {
					t.Errorf("clockSkewWarning() = %q, want no warning", warning)
				}
				return
			}

			if !strings.Contains(warning, tt.wantSub) {
				t.Errorf("clockSkewWarning() = %q, want it to contain %q", warning, tt.wantSub)
			}
			// Both clocks have to stay readable, that is the point of the warning.
			if !strings.Contains(warning, "client ") || !strings.Contains(warning, "server ") {
				t.Errorf("clockSkewWarning() = %q, want both client and server time in it", warning)
			}
		})
	}
}

func TestResponseServerTime(t *testing.T) {
	reference := time.Date(2026, 11, 17, 19, 43, 11, 0, time.UTC)

	tests := []struct {
		name   string
		header string
		want   time.Time
	}{
		{name: "Date header", header: reference.Format(http.TimeFormat), want: reference},
		{name: "missing Date header"},
		{name: "unparsable Date header", header: "not a date"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tt.header != "" {
				resp.Header.Set("Date", tt.header)
			}

			if got := responseServerTime(resp); !got.Equal(tt.want) {
				t.Errorf("responseServerTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

// authpf activate logs in from the credentials file when config.yaml holds no token.
// Both failure paths have to end in a message that says what to do next, without a
// request leaving the machine.
func TestLoginWithStoredCredentialsFailureMessages(t *testing.T) {
	tests := []struct {
		name       string
		creds      string
		perm       os.FileMode
		wantSubstr string
	}{
		{
			name:       "no credentials file",
			wantSubstr: "run auth login",
		},
		{
			name:       "credentials file readable by others",
			creds:      "username: alice\npassword: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n",
			perm:       0o644,
			wantSubstr: "incorrect permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			viper.Set(VIPER_PARAM_USERNAME, "")
			viper.Set(VIPER_PARAM_PASSWORD, "")
			t.Cleanup(func() {
				viper.Set(VIPER_PARAM_USERNAME, "")
				viper.Set(VIPER_PARAM_PASSWORD, "")
			})

			if tt.creds != "" {
				if err := os.MkdirAll(filepath.Join(home, CONFIG_DIR), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, CONFIG_DIR, CREDENTIALS_FILE), []byte(tt.creds), tt.perm); err != nil {
					t.Fatal(err)
				}
			}

			err := loginWithStoredCredentials()
			if err == nil {
				t.Fatal("loginWithStoredCredentials() succeeded, want a failure")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("loginWithStoredCredentials() = %q, want it to contain %q", err, tt.wantSubstr)
			}
		})
	}
}

// Regression: the config file carries the live bearer token and the credentials file the
// password, so neither may end up group- or world-readable, not even when the files or their
// directory already existed with a looser mode from an older release or a home restore.
func TestSecretFilesAreWrittenOwnerOnly(t *testing.T) {
	tests := []struct {
		name     string
		dirPerm  os.FileMode
		filePerm os.FileMode // 0 means neither file exists yet, the CLI creates them
	}{
		{name: "fresh install", dirPerm: 0o700},
		{name: "pre-existing loose dir and files", dirPerm: 0o755, filePerm: 0o666},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			configDir := filepath.Join(home, CONFIG_DIR)
			if err := os.MkdirAll(configDir, tt.dirPerm); err != nil {
				t.Fatal(err)
			}
			if tt.filePerm != 0 {
				for _, name := range []string{CONFIG_FILE, CREDENTIALS_FILE} {
					if err := os.WriteFile(filepath.Join(configDir, name), []byte("insecure: yes\n"), tt.filePerm); err != nil {
						t.Fatal(err)
					}
				}
			}

			viper.Set(VIPER_PARAM_AUTHPF_TOKEN, "jwt-under-test")
			t.Cleanup(func() { viper.Set(VIPER_PARAM_AUTHPF_TOKEN, "") })

			if err := saveAuthToken(); err != nil {
				t.Fatalf("saveAuthToken() = %v", err)
			}
			if err := saveCredentialsToFile("alice", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"); err != nil {
				t.Fatalf("saveCredentialsToFile() = %v", err)
			}

			assertSecretFileMode(t, filepath.Join(configDir, CONFIG_FILE), "jwt-under-test")
			assertSecretFileMode(t, filepath.Join(configDir, CREDENTIALS_FILE), "alice")

			// Logout rewrites the config file, so it must not hand back a looser mode.
			if err := clearAuthToken(); err != nil {
				t.Fatalf("clearAuthToken() = %v", err)
			}
			assertSecretFileMode(t, filepath.Join(configDir, CONFIG_FILE), "")
		})
	}
}

// assertSecretFileMode wants the file readable by its owner alone and wants wantContent to say
// whether the writer really wrote its payload or cleared it.
func assertSecretFileMode(t *testing.T, path, wantContent string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s mode = %o, want 600", path, mode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), wantContent) {
		t.Errorf("%s = %q, want it to contain %q", path, data, wantContent)
	}
}
