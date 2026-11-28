package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain pins the locale for this package. Most of the tests here assert on the symbols the
// CLI prints on purpose, and a build machine whose own LANG says ISO-8859-1 would switch the
// plain fallback on and make those tests fail for a reason unrelated to them.
func TestMain(m *testing.M) {
	os.Setenv("LC_ALL", "C.UTF-8")
	os.Unsetenv("LANG")
	os.Unsetenv(decorationEnv)

	os.Exit(m.Run())
}

// decorateWith forces one of the two looks for the rest of one test. The real decision is made
// once per process, so the cached answer has to be opened up again between tests.
func decorateWith(t *testing.T, plain bool) {
	t.Helper()

	plainOnce = sync.Once{}
	plainSet = false
	t.Cleanup(func() {
		plainOnce = sync.Once{}
		plainSet = false
	})

	if plain {
		t.Setenv(decorationEnv, "1")
	} else {
		t.Setenv(decorationEnv, "0")
	}
}

// nonASCII lists what a terminal that decodes UTF-8 cannot be asked for would make of a string.
func nonASCII(s string) []rune {
	var out []rune

	for _, r := range s {
		if r > 0x7f {
			out = append(out, r)
		}
	}

	return out
}

func TestCodesetIsUTF8(t *testing.T) {
	tests := []struct {
		name           string
		lcAll, lcCtype string
		lang           string
		want           bool
	}{
		{"nothing set at all keeps the symbols", "", "", "", true},
		{"C is a 7 bit locale", "", "", "C", false},
		{"POSIX is a 7 bit locale", "", "", "POSIX", false},
		{"a locale that names no codeset", "", "", "de_DE", false},
		{"an older codeset is taken at its word", "", "", "en_US.ISO-8859-1", false},
		{"an older codeset with a modifier", "", "", "de_DE.ISO-8859-15@euro", false},
		{"C.UTF-8 is UTF-8", "", "", "C.UTF-8", true},
		{"lowercase spelling", "", "", "en_GB.utf8", true},
		{"UTF-8 with a modifier", "", "", "en_US.UTF-8@euro", true},
		{"LC_ALL overrules LANG", "C", "", "en_US.UTF-8", false},
		{"LC_ALL overrules in the other direction too", "C.UTF-8", "", "C", true},
		{"LC_CTYPE is consulted second", "", "C.UTF-8", "C", true},
		{"LC_ALL overrules LC_CTYPE", "C", "C.UTF-8", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LC_ALL", tt.lcAll)
			t.Setenv("LC_CTYPE", tt.lcCtype)
			t.Setenv("LANG", tt.lang)

			if got := codesetIsUTF8(); got != tt.want {
				t.Errorf("codesetIsUTF8() = %v, want %v for LC_ALL=%q LC_CTYPE=%q LANG=%q",
					got, tt.want, tt.lcAll, tt.lcCtype, tt.lang)
			}
		})
	}
}

func TestDecorationOverrideSwitch(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"FALSE", false},
		{"1", true},
		{"true", true},
		{"yes", true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv(decorationEnv, tt.value)

			if got := decorationForced(); got != tt.want {
				t.Errorf("%s=%q forces plain output: %v, want %v", decorationEnv, tt.value, got, tt.want)
			}
		})
	}
}

// The decision is made once, before the first line of output, so that one run of one command
// cannot print half its lines in each of the two looks.
func TestDecorationIsDecidedOncePerRun(t *testing.T) {
	plainOnce = sync.Once{}
	plainSet = false
	t.Cleanup(func() {
		plainOnce = sync.Once{}
		plainSet = false
	})

	t.Setenv(decorationEnv, "1")
	if !plainDecorations() {
		t.Fatal("the override asked for plain output, the decision says otherwise")
	}

	t.Setenv(decorationEnv, "0")
	if !plainDecorations() {
		t.Error("the decision taken for the run was revised half way through it")
	}
}

func TestMarkAndAltFollowTheDecision(t *testing.T) {
	decorateWith(t, false)

	if got := mark("✅ "); got != "✅ " {
		t.Errorf("mark() dropped a symbol it was handed: %q", got)
	}
	if got := mark(""); got != "" {
		t.Errorf("mark() invented something for an empty symbol: %q", got)
	}
	if got := alt(" …", "..."); got != " …" {
		t.Errorf("alt() = %q, want the UTF-8 form", got)
	}

	decorateWith(t, true)

	for _, symbol := range []string{"✅ ", "❌ ", "⚠️ ", "⚠️  "} {
		if got := mark(symbol); got != "" {
			t.Errorf("plain output still carries %q", got)
		}
	}
	if got := alt(" …", "..."); got != "..." {
		t.Errorf("alt() = %q, want the ASCII stand-in", got)
	}
}

// The error line is the one message users of this tool see most often, and it is the reason
// the fallback exists at all: "❌ Error:" is exactly the mojibake people run into.
func TestErrorLineStaysInsideASCIIWhenTheLocaleAsksForIt(t *testing.T) {
	decorateWith(t, true)

	out := captureStderr(t, func() {
		ReportError(errors.New(`anchor "gw1" rejected the request`))
	})

	if left := nonASCII(out); len(left) > 0 {
		t.Errorf("a locale that cannot decode UTF-8 was handed these characters: %q in %q", left, out)
	}
	if !strings.HasPrefix(out, "Error: ") {
		t.Errorf("plain error line lost the word that says it is an error: %q", out)
	}

	decorateWith(t, false)

	out = captureStderr(t, func() {
		ReportError(errors.New(`anchor "gw1" rejected the request`))
	})
	if !strings.HasPrefix(out, "❌ Error: ") {
		t.Errorf("with a UTF-8 locale the error line should look exactly like it did: %q", out)
	}
}

// A truncated message has to say so in plain mode too; dropping the ellipsis would leave a
// sentence that looks complete.
func TestTruncatedMessageStillSaysItWasTruncated(t *testing.T) {
	long := strings.Repeat("x", maxReportedErrorChars+10)

	decorateWith(t, true)

	out := strings.TrimSuffix(captureStderr(t, func() { ReportError(errors.New(long)) }), "\n")
	if !strings.HasSuffix(out, "...") {
		t.Errorf("truncation left no trace in plain output: %q", out[len(out)-40:])
	}

	decorateWith(t, false)

	out = strings.TrimSuffix(captureStderr(t, func() { ReportError(errors.New(long)) }), "\n")
	if !strings.HasSuffix(out, " …") {
		t.Errorf("truncation marker changed in a UTF-8 locale: %q", out[len(out)-40:])
	}
}

// The open box marks a character the user cannot see, which is a statement, not decoration, so
// plain mode needs a substitute for it rather than silence.
func TestInvisibleCharactersAreStillMarked(t *testing.T) {
	decorateWith(t, true)

	if got := sanitizeDisplay("del\timited"); got != "del?imited" {
		t.Errorf("sanitizeDisplay() in plain mode = %q, want the ? marker", got)
	}

	decorateWith(t, false)

	if got := sanitizeDisplay("del\timited"); got != "del␣imited" {
		t.Errorf("sanitizeDisplay() with a UTF-8 locale = %q, want the open box", got)
	}
}

// The symbols are only reachable through mark() and alt(), and a line that gets one without
// that wrapper is a line some future terminal will show as mojibake. Checked against the
// source because the plain fallback is invisible in a test run on a UTF-8 machine otherwise.
func TestStatusSymbolsAreReachedThroughTheDecisionOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "decoration") {
			continue
		}

		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}

		for number, line := range strings.Split(string(source), "\n") {
			if !carriesStatusSymbol(line) || strings.Contains(line, "mark(") || strings.Contains(line, "alt(") {
				continue
			}

			t.Errorf("%s:%d hands out a status symbol the terminal was never asked about: %s",
				name, number+1, strings.TrimSpace(line))
		}
	}
}

func carriesStatusSymbol(line string) bool {
	for _, symbol := range []string{"✅", "❌", "⚠", "…"} {
		if strings.Contains(line, symbol) {
			return true
		}
	}

	return false
}

// The words next to a symbol are what people and scripts match on, and they sit in the same
// string literal as the symbol does. Shaving the symbol off there has happened once already
// while these lines were being wrapped, so the wording is pinned. Checked as literal text
// rather than as whole lines, because gofmt joins a concatenation with or without spaces
// depending on where it stands and that layout is not what this is about.
func TestDecoratedLinesKeepTheirWords(t *testing.T) {
	wanted := []struct {
		file, wording string
	}{
		{"auth.go", `"Warning: failed to save credentials file`},
		{"auth.go", `"Successfully logged in as %s`},
		{"auth.go", `"Credentials saved to credentials file"`},
		{"auth.go", `"Successfully logged out"`},
		{"auth.go", `"Token Validation: "`},
		{"auth.go", `"Valid")`},
		{"authpf.go", `"Logged in from stored credentials"`},
		{"authpf.go", `"AuthPF anchor status: active`},
		{"authpf.go", `"AuthPF anchor status: inactive"`},
		{"sanitize.go", `"Error: %s`},
	}

	for _, want := range wanted {
		source, err := os.ReadFile(want.file)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(source), want.wording) {
			t.Errorf("cmd/%s no longer contains %s", want.file, want.wording)
		}
	}
}

// The status report and the clock warning are built from format strings rather than printed
// directly, so they are checked on their own.
func TestStatusAndClockLinesArePlainToo(t *testing.T) {
	decorateWith(t, true)

	status := &AuthPFStatus{
		Username:  "alice",
		UserIP:    "10.0.0.7",
		UserID:    42,
		Timeout:   "3600",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	behind := formatAuthPFStatus(status, time.Now())
	if left := nonASCII(behind); len(left) > 0 {
		t.Errorf("the status report is not plain: %q", left)
	}
	if !strings.HasPrefix(behind, "AuthPF anchor status: active") {
		t.Errorf("the status report lost its wording on the way: %q", behind)
	}

	for _, serverTime := range []time.Time{time.Now().Add(24 * time.Hour), time.Now().Add(-24 * time.Hour)} {
		warning := clockSkewWarning(serverTime)
		if left := nonASCII(warning); len(left) > 0 {
			t.Errorf("the clock warning is not plain: %q", left)
		}
		if !strings.Contains(warning, "Time difference") {
			t.Errorf("the clock warning lost its wording: %q", warning)
		}
	}
}
