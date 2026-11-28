package cmd

import (
	"os"
	"strings"
	"sync"
)

// decorationEnv is the escape hatch for the one case no detection can cover: a terminal that
// decodes UTF-8 perfectly well but has no glyphs for the status symbols, which leaves an empty
// box where the checkmark was. Neither terminfo nor any query tells a program what fonts are
// installed, so the person sitting in front of the screen decides here.
const decorationEnv = "AUTHPF_CLI_PLAIN"

// mark returns symbol when the terminal in front of the tool can be expected to render it, and
// nothing at all otherwise. Every line a symbol leads already says in words what the symbol
// says in colour, so dropping it costs decoration and no information.
func mark(symbol string) string {
	if plainDecorations() {
		return ""
	}

	return symbol
}

// ellipsis closes a message the tool cut short. Unlike the status symbols it carries a meaning
// of its own - "there was more to read" - so it cannot simply go missing: a code page that
// cannot draw U+2026 gets three dots, which says the same thing in seven bits.
func ellipsis() string {
	if plainDecorations() {
		return "..."
	}

	return " …"
}

var (
	plainOnce sync.Once
	plainSet  bool
)

// plainDecorations is worked out once, before the first line leaves the tool, and never again:
// a single run of a single command should not print half its lines in each of the two looks.
func plainDecorations() bool {
	plainOnce.Do(func() {
		plainSet = decorationForced() || !codesetIsUTF8() || !consoleIsUTF8()
	})

	return plainSet
}

// decorationForced reads the escape hatch. Only an empty value, "0" and "false" keep the
// symbols, so AUTHPF_CLI_PLAIN=1 and AUTHPF_CLI_PLAIN=yes both do what they say.
func decorationForced() bool {
	switch strings.ToLower(os.Getenv(decorationEnv)) {
	case "", "0", "false":
		return false
	}

	return true
}

// codesetIsUTF8 reads the codeset the way POSIX reads it: LC_ALL beats LC_CTYPE beats LANG, and
// whichever of the three is set first is the only one that counts.
//
// A locale that names a codeset older than Unicode is taken at its word - "C", "POSIX" and a
// bare "de_DE" are 7 bit locales, and handing their terminals the three bytes of a checkmark is
// what turns the output into "ÔØî". A locale that is not set at all keeps the symbols: the
// terminal decodes those bytes itself and often ignores the shell's locale entirely, so an
// unset LANG says far less about a screen than a locale that positively claims an old codeset.
func codesetIsUTF8() bool {
	name := os.Getenv("LC_ALL")
	if name == "" {
		name = os.Getenv("LC_CTYPE")
	}
	if name == "" {
		name = os.Getenv("LANG")
	}
	if name == "" {
		return true
	}

	if at := strings.IndexRune(name, '@'); at >= 0 {
		name = name[:at]
	}

	dot := strings.IndexRune(name, '.')
	if dot < 0 {
		return false
	}

	codeset := name[dot+1:]

	return strings.EqualFold(codeset, "UTF-8") || strings.EqualFold(codeset, "UTF8")
}
