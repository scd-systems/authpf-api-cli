package cmd

import (
	"os"
	"strings"
	"testing"
	"unicode"
)

// captureStderr and captureStdout redirect the two channels the CLI reports on so a test
// can assert on what a user would actually see. A temp file rather than a pipe: the
// megabyte sized cases below would block an unread pipe.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return captureFile(t, &os.Stderr, fn)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureFile(t, &os.Stdout, fn)
}

func captureFile(t *testing.T, target **os.File, fn func()) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "capture")
	if err != nil {
		t.Fatal(err)
	}
	original := *target
	*target = file
	defer func() { *target = original }()

	fn()

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// nonPrintable names the first rune a terminal would act on instead of print. Zero means
// the text holds none, which is what a single field value has to look like.
func nonPrintable(s string) rune {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return r
		}
	}
	return 0
}

// firstInjectedControl is nonPrintable for whole output, where the line feeds between the
// tool's own lines are expected and only a control character inside them counts.
func firstInjectedControl(s string) rune {
	for _, r := range s {
		if r != '\n' && !unicode.IsPrint(r) {
			return r
		}
	}
	return 0
}

// TestSanitizeDisplay is the regression gate for the escape sequence injection: every case
// below reaches a real terminal unchanged when sanitizeDisplay is dropped from the output
// path.
func TestSanitizeDisplay(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "osc 0 title set", in: "alice\u001b]0;PWNED-BY-SERVER\u0007alice", want: "alice␣]0;PWNED-BY-SERVER␣alice"},
		{name: "osc 52 clipboard write", in: "a\u001b]52;c;c2VjcmV0X3N0dWZm\u0007", want: "a␣]52;c;c2VjcmV0X3N0dWZm␣"},
		{name: "csi erase and colour", in: "\u001b[2J\u001b[31mroot\u001b[0m", want: "␣[2J␣[31mroot␣[0m"},
		{name: "osc 8 hyperlink", in: "\u001b]8;;http://phish.example\u0007click", want: "␣]8;;http://phish.example␣click"},
		{name: "cr overwrite", in: "alice\r\n  Username: root", want: "alice␣␣  Username: root"},
		{name: "newline fabricated line", in: "alice\n  Expire In: 9999d", want: "alice␣  Expire In: 9999d"},
		{name: "tab", in: "a\tb", want: "a␣b"},
		{name: "nul and del", in: "a\x00b\x7fc", want: "a␣b␣c"},
		// The two cases a plain r >= 0x20 filter passes straight through, because both
		// arrive as well formed UTF-8 runes above 0x20.
		{name: "c1 csi introducer", in: "alice\u009b0;C1-TITLE-PWNED\u009b2J", want: "alice␣0;C1-TITLE-PWNED␣2J"},
		{name: "c1 string terminator", in: "alice\u009d0;OSC\u009d", want: "alice␣0;OSC␣"},
		// Also not control characters, but they still rearrange or hide what is read.
		{name: "rtl override", in: "a\u202eb", want: "a␣b"},
		{name: "zero width space", in: "ro\u200bot", want: "ro␣ot"},
		// Values a real server sends must come out byte for byte the same.
		{name: "ascii user and ipv4", in: "Fritz_9-Walter 10.0.0.42 2001:db8::42 8h", want: "Fritz_9-Walter 10.0.0.42 2001:db8::42 8h"},
		{name: "umlauts and symbols", in: "Äöüß → · ␣", want: "Äöüß → · ␣"},
		{name: "empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeDisplay(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeDisplay(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if r := nonPrintable(got); r != 0 {
				t.Errorf("sanitizeDisplay(%q) = %q still carries U+%04X", tt.in, got, r)
			}
		})
	}
}

// Undecodable bytes are the one input that is not a rune at all, so the exact rendering is
// open, but no byte of it may be an escape.
func TestSanitizeDisplayInvalidUTF8(t *testing.T) {
	got := sanitizeDisplay("alice\xff\xfe\u001b]0;x\u0007")

	for _, b := range []byte{0x07, 0x0d, 0x0a, 0x1b, 0x7f} {
		if strings.ContainsRune(got, rune(b)) {
			t.Errorf("sanitizeDisplay() = %q still carries 0x%02x", got, b)
		}
	}
}

func TestReportError(t *testing.T) {
	t.Run("filters a hostile server body", func(t *testing.T) {
		err := &hostileError{msg: "login failed with status 401: \u001b]0;root@core-gw\u0007denied\r"}

		out := captureStderr(t, func() { ReportError(err) })

		if !strings.HasPrefix(out, "❌ Error: ") {
			t.Errorf("ReportError() printed %q, want the usual ❌ Error: prefix", out)
		}
		if r := firstInjectedControl(out); r != 0 {
			t.Errorf("ReportError() printed U+%04X, the raw error is %q", r, err.Error())
		}
		// Without this the case would pass even with the sanitizer removed.
		if nonPrintable(err.Error()) == 0 {
			t.Fatal("test setup is broken, the error carries no control character to filter")
		}
	})

	t.Run("bounds a megabyte sized body", func(t *testing.T) {
		out := captureStderr(t, func() { ReportError(&hostileError{msg: strings.Repeat("a", maxReportedErrorChars*3)}) })

		if got := len([]rune(strings.TrimSuffix(out, "\n"))); got > maxReportedErrorChars+len("❌ Error: …") {
			t.Errorf("ReportError() printed %d characters, want it bounded at about %d", got, maxReportedErrorChars)
		}
	})
}

// hostileError stands in for an error built around a server response body.
type hostileError struct{ msg string }

func (e *hostileError) Error() string { return e.msg }
