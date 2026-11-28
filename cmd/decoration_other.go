//go:build !windows

package cmd

// consoleIsUTF8 leaves the decision to the locale everywhere else: no other platform lets the
// console choose a code page of its own behind the locale's back.
func consoleIsUTF8() bool {
	return true
}
