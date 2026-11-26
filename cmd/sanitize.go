package cmd

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// sanitizeDisplay replaces every character a terminal would act on instead of printing it.
// unicode.IsPrint is deliberate here rather than a r < 0x20 test: the C1 controls arrive as
// perfectly ordinary UTF-8 runes (CSI U+009B, OSC/STRING terminator U+009D) and walk
// through a r < 0x20 filter untouched, and the Unicode format characters (RTL override
// U+202E, zero width space U+200B) let a server hide or reorder what the user reads without
// being control characters at all. Newline and carriage return are replaced as well, so a
// response cannot fabricate lines that look like this tool's own output.
func sanitizeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '\u2423' // open box: something invisible was here
		}
		return r
	}, s)
}

// maxReportedErrorChars bounds a single error line. Response bodies end up inside error
// strings, and an endpoint is free to answer with megabytes of them.
const maxReportedErrorChars = 512

// ReportError prints a command failure as the last line the user sees. Every error string
// can carry text taken straight out of a server response, so this is the one place where
// those strings get filtered on their way to the terminal.
func ReportError(err error) {
	msg := err.Error()
	if r := []rune(msg); len(r) > maxReportedErrorChars {
		msg = string(r[:maxReportedErrorChars]) + " …"
	}
	fmt.Fprintf(os.Stderr, "❌ Error: %s\n", sanitizeDisplay(msg))
}
