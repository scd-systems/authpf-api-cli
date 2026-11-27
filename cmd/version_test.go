package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestParseVersion verifies that parseVersion correctly parses semantic versions.
func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		major   int
		minor   int
		wantErr bool
	}{
		{"2.1", 2, 1, false},
		{"0.0", 0, 0, false},
		{"10.20", 10, 20, false},
		{"invalid", 0, 0, true},
		{"1.2", 1, 2, false},
	}
	for _, tt := range tests {
		major, minor, err := parseVersion(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("parseVersion(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && (major != tt.major || minor != tt.minor) {
			t.Fatalf("parseVersion(%s) = %d.%d, want %d.%d", tt.input, major, minor, tt.major, tt.minor)
		}
	}
}

// TestCompareVersions checks compatibility logic (major and minor must match).
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		cli    string
		srv    string
		wantOK bool
	}{
		{"2.0", "2.0", true},
		{"2.1", "2.1", true},
		{"1.9", "2.0", false},
		{"2.0", "2.1", false},
	}
	for _, tt := range tests {
		err := compareAPIVersions(tt.cli, tt.srv)
		if (err == nil) != tt.wantOK {
			t.Fatalf("compareVersions(%s,%s) error = %v, wantOK %v", tt.cli, tt.srv, err, tt.wantOK)
		}
	}
}

// TestGetServerInfoHonoursItsTimeout is the reason the request helpers take a configuration
// at all: getServerInfo was handed one and used the default anyway, so --version waited the
// full 30 seconds of DefaultHTTPConfig on a server that was not answering.
func TestGetServerInfoHonoursItsTimeout(t *testing.T) {
	// A handler that never answers, and gives up with the client instead of holding the
	// test server open.
	srv := hostileServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	clientAt(t, srv)

	config := DefaultHTTPConfig()
	config.Timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := getServerInfo(config)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a server that never answered was treated as an answer")
	}
	if elapsed > time.Second {
		t.Errorf("waited %s for a %s timeout", elapsed, config.Timeout)
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("error is %v, wanted a timeout", err)
	}
}

// TestGetServerInfoStillReadsAFastServer keeps the other half of the promise: one second is
// a ceiling, not a new expectation of how fast a server has to be to be understood.
func TestGetServerInfoStillReadsAFastServer(t *testing.T) {
	srv := hostileServer(t, map[string]canned{
		"GET " + ENDPOINT_INFO: {http.StatusOK, okInfo},
	})
	clientAt(t, srv)

	config := DefaultHTTPConfig()
	config.Timeout = versionProbeTimeout

	info, err := getServerInfo(config)
	if err != nil {
		t.Fatalf("answering server was refused: %v", err)
	}
	if info.Version != "1.0" || info.API_Version != "1.2" {
		t.Errorf("read %q / %q, wanted 1.0 / 1.2", info.Version, info.API_Version)
	}
}

func TestDisplayVersionInfoNotesASlowServer(t *testing.T) {
	srv := hostileServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	clientAt(t, srv)

	start := time.Now()
	out := captureStdout(t, func() {
		if err := DisplayVersionInfo("1.2.3"); err != nil {
			t.Errorf("DisplayVersionInfo: %v", err)
		}
	})
	elapsed := time.Since(start)

	// The point of the change: a server that never answers costs about a second. Generous
	// ceiling, because a loaded machine schedules the timer late.
	if elapsed > 5*time.Second {
		t.Errorf("waited %s for the version probe", elapsed)
	}

	info := decodeVersionInfo(t, out)
	if info.CLIVersion != "1.2.3" {
		t.Errorf("client_version is %q", info.CLIVersion)
	}
	if info.APIVersion != API_VERSION {
		t.Errorf("client_supported_api is %q", info.APIVersion)
	}
	if info.ServerVersion != "" || info.ServerAPIVersion != "" {
		t.Errorf("server fields were filled in without a server: %+v", info)
	}
	if !strings.Contains(info.ServerNote, versionProbeTimeout.String()) {
		t.Errorf("note %q does not name the timeout", info.ServerNote)
	}
}

// TestDisplayVersionInfoNotesAnUnreachableServer uses a port that was open and is not
// anymore, which is the connection refused case rather than the timeout case.
func TestDisplayVersionInfoNotesAnUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	address := srv.URL
	srv.Close()

	t.Cleanup(func() { viper.Set(VIPER_PARAM_SERVER, "") })
	viper.Set(VIPER_PARAM_SERVER, address)

	out := captureStdout(t, func() {
		if err := DisplayVersionInfo("1.2.3"); err != nil {
			t.Errorf("DisplayVersionInfo: %v", err)
		}
	})

	info := decodeVersionInfo(t, out)
	if !strings.Contains(info.ServerNote, "not reachable") {
		t.Errorf("note is %q, wanted the unreachable wording", info.ServerNote)
	}
}

// --version is not allowed to fail because a server does not answer: it is the command an
// operator reaches for while finding out why.
func TestDisplayVersionInfoSucceedsWithoutAServer(t *testing.T) {
	t.Cleanup(func() { viper.Set(VIPER_PARAM_SERVER, "") })
	viper.Set(VIPER_PARAM_SERVER, "http://127.0.0.1:1")

	captureStdout(t, func() {
		if err := DisplayVersionInfo("1.2.3"); err != nil {
			t.Fatalf("DisplayVersionInfo failed over a missing server: %v", err)
		}
	})
}

func TestServerProbeNoteNamesTheTimeout(t *testing.T) {
	// What the HTTP client hands back when its own deadline passes.
	slow := &url.Error{Op: "Get", URL: "http://server.example/info", Err: context.DeadlineExceeded}

	note := serverProbeNote(fmt.Errorf("failed to send request: %w", slow))
	if !strings.Contains(note, versionProbeTimeout.String()) {
		t.Errorf("note %q does not name the timeout", note)
	}
	if strings.Contains(note, "server.example") {
		t.Errorf("note %q repeats the configured URL back", note)
	}
}

// Defence in depth rather than a live path: today the errors that reach here come from the
// transport, not from a response body. The version output is printed straight, without
// passing ReportError, so it filters its own text like everything else that does.
func TestServerProbeNoteFiltersControlCharacters(t *testing.T) {
	note := serverProbeNote(errors.New("refused\u001b]0;PWNED-BY-SERVER\u0007"))

	if strings.ContainsAny(note, "\x1b\x07") {
		t.Errorf("note carries terminal control characters: %q", note)
	}
	if !strings.Contains(note, "␣]0;PWNED-BY-SERVER␣") {
		t.Errorf("note does not show what was filtered: %q", note)
	}
}

// decodeVersionInfo reads back the JSON the command prints.
func decodeVersionInfo(t *testing.T, out string) versionInfo {
	t.Helper()

	var info versionInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("version output is not the JSON it should be: %v\n%s", err, out)
	}

	return info
}

// The version answer is printed before Cobra parses the command line, which is why --config
// has to be read by hand for it: without it, --version asks the server of whichever file it
// happens to fall back to rather than the one the user named.
func TestVersionRequestedFindsItsArguments(t *testing.T) {
	cases := []struct {
		args       []string
		wanted     bool
		configPath string
	}{
		{args: []string{"--version"}, wanted: true},
		{args: []string{"auth", "login", "-V"}, wanted: true},
		{args: []string{"--config", "other.yaml", "--version"}, wanted: true, configPath: "other.yaml"},
		{args: []string{"--version", "--config=other.yaml"}, wanted: true, configPath: "other.yaml"},
		{args: []string{"user", "list"}, wanted: false},
		// A flag at the very end has no value to pick up, and must not swallow anything.
		{args: []string{"--version", "--config"}, wanted: true},
	}

	for _, tc := range cases {
		wanted, configPath := versionRequested(tc.args)
		if wanted != tc.wanted || configPath != tc.configPath {
			t.Errorf("versionRequested(%q) = %v %q, want %v %q",
				tc.args, wanted, configPath, tc.wanted, tc.configPath)
		}
	}
}
