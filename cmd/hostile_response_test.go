package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// The payloads below are the ones from the vuln-0003 report, kept as that report sent them:
// they stand in for what an endpoint answers for the configured api.server.

// What must never reach the terminal.
const (
	oscTitle     = "\u001b]0;PWNED-BY-SERVER\u0007"
	oscClipboard = "\u001b]52;c;cGFzdGUtbWU=\u0007"
	csiErase     = "\u001b[2J\u001b[31m"
)

// The same sequences as a server sends them in JSON. encoding/json refuses a raw 0x1b
// inside a string, so the sequences travel escaped and the decoder is what hands the real
// escape characters to us: anything that filtered the response bytes before the decode
// would catch nothing at all.
const (
	jsonOscTitle     = `\u001b]0;PWNED-BY-SERVER\u0007`
	jsonOscClipboard = `\u001b]52;c;cGFzdGUtbWU=\u0007`
	jsonCsiErase     = `\u001b[2J\u001b[31m`
)

const (
	// hostileBody is a non JSON error body, which is what the error paths echo verbatim.
	hostileBody = "denied" + oscTitle + csiErase + "\r  Username: root"

	okInfo = `{"api_version":"1.2","server_version":"1.0"}`
)

// canned is one scripted endpoint answer, keyed by "METHOD /path".
type canned struct {
	status int
	body   string
}

// hostileServer answers the given bodies and nothing else.
func hostileServer(t *testing.T, responses map[string]canned) *httptest.Server {
	return hostileServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		res, ok := responses[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.status)
		_, _ = w.Write([]byte(res.body))
	})
}

// hostileServerFunc serves whatever the handler does, for the cases that are about the
// response size rather than its content.
func hostileServerFunc(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// clientAt points the client at srv and clears the settings afterwards, so the next test
// does not inherit a URL.
func clientAt(t *testing.T, srv *httptest.Server) {
	t.Helper()

	keys := []string{
		VIPER_PARAM_SERVER, VIPER_PARAM_AUTHPF_TOKEN, VIPER_PARAM_USERNAME,
		VIPER_PARAM_PASSWORD, VIPER_PARAM_AUTHPF_USERNAME,
	}
	for _, key := range keys {
		key := key
		t.Cleanup(func() { viper.Set(key, "") })
	}

	viper.Set(VIPER_PARAM_SERVER, srv.URL)
	viper.Set(VIPER_PARAM_AUTHPF_TOKEN, "stored-token-0123456789")
	viper.Set(VIPER_PARAM_USERNAME, "alice")
	viper.Set(VIPER_PARAM_PASSWORD, "Passw0rd_1")
	viper.Set(VIPER_PARAM_AUTHPF_USERNAME, "")
}

// TestAnchorResponseIsSanitisedAtTheParseBoundary feeds the report's hostile anchor
// document through the real request path and asserts that nothing the renderers can print
// still carries a character a terminal would act on.
func TestAnchorResponseIsSanitisedAtTheParseBoundary(t *testing.T) {
	body := `{"anchors":{` +
		`"anchor\u001b]0;PWNED-TITLE\u0007":null,` +
		`"alice":{"username":"` + jsonOscTitle + `alice","user_ip":"` + jsonOscClipboard + `",` +
		`"user_id":1,"timeout":"` + jsonCsiErase + `1h","expire_at":"2030-01-01T00:00:00Z"}}}`

	srv := hostileServer(t, map[string]canned{
		"GET " + ENDPOINT_INFO:       {http.StatusOK, okInfo},
		"GET " + ENDPOINT_AUTHPF_ALL: {http.StatusOK, body},
	})
	clientAt(t, srv)

	data, err := getAuthPFAnchorStatus(true)
	if err != nil {
		t.Fatalf("getAuthPFAnchorStatus() = %v", err)
	}
	response, ok := data.(*AuthPFAnchorsResponse)
	if !ok {
		t.Fatalf("getAuthPFAnchorStatus() returned %T", data)
	}

	var printable strings.Builder
	for key, status := range response.Anchors {
		printable.WriteString(key)
		if status == nil {
			continue
		}
		printable.WriteString(formatAuthPFStatus(status, response.ServerTime))
		printable.WriteString(formatAuthPFStatusDetailed(status, response.ServerTime))
	}

	if printable.Len() == 0 {
		t.Fatal("nothing was parsed out of the response, the test proves nothing")
	}
	if r := firstInjectedControl(printable.String()); r != 0 {
		t.Errorf("parsed response still carries U+%04X to be printed: %q", r, printable.String())
	}
}

// TestStatusAllToleratesNilAnchor covers the segmentation violation on
// {"anchors":{"alice":null,...}} with --all.
func TestStatusAllToleratesNilAnchor(t *testing.T) {
	anchors := `{"anchors":{"` + jsonOscTitle + `alice":null,"bob":{"username":"bob","user_ip":"10.0.0.7","user_id":2,"timeout":"8h"}}}`

	srv := hostileServer(t, map[string]canned{
		"GET " + ENDPOINT_INFO:       {http.StatusOK, okInfo},
		"GET " + ENDPOINT_LOGIN:      {http.StatusOK, `{"ok":true}`},
		"GET " + ENDPOINT_AUTHPF_ALL: {http.StatusOK, anchors},
	})
	clientAt(t, srv)

	t.Cleanup(func() { _ = authpfStatusCmd.Flags().Set("all", "false") })
	if err := authpfStatusCmd.Flags().Set("all", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := authpfStatusCmd.RunE(authpfStatusCmd, nil); err != nil {
			t.Errorf("authpf status --all = %v", err)
		}
	})

	for _, want := range []string{"Total active anchors: 1", "Username: bob", "(no status reported for this anchor)"} {
		if !strings.Contains(out, want) {
			t.Errorf("authpf status --all printed:\n%s\nwant it to contain %q", out, want)
		}
	}
	if r := firstInjectedControl(out); r != 0 {
		t.Errorf("authpf status --all printed U+%04X: %q", r, out)
	}
}

// TestStatusWithoutAllSkipsNilAnchor is the sibling case: the single anchor path picked the
// nil entry first and reported "no active anchors" while another anchor was live.
func TestStatusWithoutAllSkipsNilAnchor(t *testing.T) {
	srv := hostileServer(t, map[string]canned{
		"GET " + ENDPOINT_INFO:            {http.StatusOK, okInfo},
		"GET " + ENDPOINT_LOGIN:           {http.StatusOK, `{"ok":true}`},
		"GET " + ENDPOINT_AUTHPF_ACTIVATE: {http.StatusOK, `{"anchors":{"alice":null,"bob":{"username":"bob","user_ip":"10.0.0.7","user_id":2}}}`},
	})
	clientAt(t, srv)

	out := captureStdout(t, func() {
		if err := authpfStatusCmd.RunE(authpfStatusCmd, nil); err != nil {
			t.Errorf("authpf status = %v", err)
		}
	})

	if !strings.Contains(out, "Username: bob") {
		t.Errorf("authpf status printed:\n%s\nwant the live anchor bob, not the null entry", out)
	}
}

// TestErrorSinksPrintNoControlBytes walks every site that puts a response body into an
// error message. The bodies are deliberately left unsanitised at those sites, so the
// failure has to be caught where the error is printed.
func TestErrorSinksPrintNoControlBytes(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]canned
		run       func() error
	}{
		{
			name: "activate",
			responses: map[string]canned{
				"GET " + ENDPOINT_INFO:             {http.StatusOK, okInfo},
				"POST " + ENDPOINT_AUTHPF_ACTIVATE: {http.StatusForbidden, hostileBody},
			},
			run: activateAuthPFAnchor,
		},
		{
			name: "deactivate",
			responses: map[string]canned{
				"GET " + ENDPOINT_INFO:               {http.StatusOK, okInfo},
				"DELETE " + ENDPOINT_AUTHPF_ACTIVATE: {http.StatusForbidden, hostileBody},
			},
			run: func() error { return deactivateAuthPFAnchor(false) },
		},
		{
			name: "login",
			responses: map[string]canned{
				"GET " + ENDPOINT_INFO:   {http.StatusOK, okInfo},
				"POST " + ENDPOINT_LOGIN: {http.StatusUnauthorized, hostileBody},
			},
			run: func() error { _, _, err := performLogin(); return err },
		},
		{
			name:      "token validation probe",
			responses: map[string]canned{"GET " + ENDPOINT_LOGIN: {http.StatusForbidden, hostileBody}},
			run:       func() error { _, err := validateTokenAgainstServer(); return err },
		},
		{
			name: "api version gate",
			responses: map[string]canned{
				"GET " + ENDPOINT_INFO: {http.StatusOK, `{"api_version":"` + jsonOscTitle + `bogus","server_version":"1.0"}`},
			},
			run: checkAPIVersionCompatibility,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientAt(t, hostileServer(t, tt.responses))

			err := tt.run()
			if err == nil {
				t.Fatal("the command succeeded, want the failure the endpoint caused")
			}
			// The payload has to reach the error string, otherwise the case below would
			// pass with the sanitizer in ReportError removed.
			if nonPrintable(err.Error()) == 0 {
				t.Fatalf("test setup is broken, %q carries no control character", err)
			}

			out := captureStderr(t, func() { ReportError(err) })

			if !strings.HasPrefix(out, "❌ Error: ") {
				t.Errorf("printed %q, want the usual ❌ Error: prefix", out)
			}
			if r := firstInjectedControl(out); r != 0 {
				t.Errorf("printed U+%04X from the response body: %q", r, out)
			}
		})
	}
}

// TestAuthTokenCoversEveryTokenLength covers the slice panic on a server issued token
// shorter than the 10 characters shown, and the same echo as an escape sink.
func TestAuthTokenCoversEveryTokenLength(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"shorter than the shown prefix", "AB12", "Current Token: AB12....\n"},
		{"exactly the shown prefix", "0123456789", "Current Token: 0123456789....\n"},
		{"longer than the shown prefix", "abcdefghijklmnop", "Current Token: abcdefghij....\n"},
		{"hostile token", oscTitle + "abcdefghij", "Current Token: ␣]0;PWNED-....\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { viper.Set(VIPER_PARAM_AUTHPF_TOKEN, "") })
			viper.Set(VIPER_PARAM_AUTHPF_TOKEN, tt.token)

			out := captureStdout(t, func() {
				if err := authTokenCmd.RunE(authTokenCmd, nil); err != nil {
					t.Errorf("auth token = %v", err)
				}
			})

			if out != tt.want {
				t.Errorf("auth token printed %q, want %q", out, tt.want)
			}
		})
	}
}

// TestResponseSizeLimit bounds what a response may cost the client. Both sides of the
// limit matter: one byte too many must fail, a full body must not.
func TestResponseSizeLimit(t *testing.T) {
	srv := hostileServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), size))
	})

	tests := []struct {
		name      string
		size      int
		wantError bool
	}{
		{"body of exactly the limit", maxResponseBytes, false},
		{"one byte past the limit", maxResponseBytes + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := sendRequest(srv.URL+"/?size="+strconv.Itoa(tt.size), "GET")

			if tt.wantError && (err == nil || !strings.Contains(err.Error(), "exceeds")) {
				t.Errorf("sendRequest() = %v, want a refusal to buffer the body", err)
			}
			if !tt.wantError && err != nil {
				t.Errorf("sendRequest() = %v, want a body at the limit to be accepted", err)
			}
		})
	}
}

// TestOversizedResponseIsRefusedWithoutReadingItOut closes the gap the case above leaves.
// A client that buffered a body of any size and only then complained about it would still
// pass that case, with the right error message. So this endpoint hands out one byte past
// the limit and then stays open forever, the way a stream does: the client has to give up
// on its own rather than sit there waiting for an end that never comes.
func TestOversizedResponseIsRefusedWithoutReadingItOut(t *testing.T) {
	srv := hostileServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for sent := 0; sent <= maxResponseBytes; {
			n := len(chunk)
			if maxResponseBytes+1-sent < n {
				n = maxResponseBytes + 1 - sent
			}
			wrote, err := w.Write(chunk[:n])
			sent += wrote
			if err != nil || wrote == 0 {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		// The response is never finished. Bounded so that a client which does keep reading
		// cannot hang the test binary on the way out.
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})

	// A client that refuses to buffer the body comes back in milliseconds.
	done := make(chan error, 1)
	go func() { _, _, err := sendRequest(srv.URL, "GET"); done <- err }()

	var err error
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the client is still reading a response it should have refused at the limit")
	}

	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("sendRequest() = %v, want a refusal to buffer the body", err)
	}
}

// TestBenignAnchorRendersUnchanged is the counterpart: a normal server answer must still
// come out byte for byte the way it always did.
func TestBenignAnchorRendersUnchanged(t *testing.T) {
	expires := time.Date(2026, 11, 26, 15, 4, 5, 0, time.UTC)
	serverTime := time.Date(2026, 11, 26, 5, 4, 5, 0, time.UTC)
	status := &AuthPFStatus{
		Username:  "Fritz_9",
		UserIP:    "10.0.0.42",
		UserID:    1001,
		Timeout:   "8h",
		ExpiresAt: expires,
	}

	want := "✅ AuthPF anchor status: active\n" +
		"  Username: Fritz_9\n" +
		"  UserIP: 10.0.0.42\n" +
		"  UserID: 1001\n" +
		"  Timeout: 8h\n" +
		"  Expire At: 2026-11-26 03:04 PM\n" +
		"  Expire In: 10h 0m"

	if got := formatAuthPFStatus(status, serverTime); got != want {
		t.Errorf("formatAuthPFStatus() =\n%s\nwant\n%s", got, want)
	}
}
