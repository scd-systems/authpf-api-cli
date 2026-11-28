//go:build windows

package cmd

import "golang.org/x/sys/windows"

// utf8CodePage is what the console has to be set to, with chcp 65001 or a recent terminal
// default, to read the bytes this tool writes as characters instead of as code page noise.
const utf8CodePage = 65001

// consoleIsUTF8 asks the console itself, because on Windows the console picks a code page of
// its own no matter what the locale claims. A console left on CP437 or CP850 has no way to
// show any of the status symbols and prints two or three accented letters for each of them.
func consoleIsUTF8() bool {
	codePage, err := windows.GetConsoleOutputCP()
	if err != nil {
		return false
	}

	return codePage == utf8CodePage
}
