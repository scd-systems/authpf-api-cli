package main

import (
	"fmt"
	"os"

	"scd-systems.net/authpf-api-cli/cmd"
)

var Version = "dev"

func main() {
	if err := cmd.Execute(Version); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}
