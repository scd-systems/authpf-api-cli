package main

import (
	"os"

	"scd-systems.net/authpf-api-cli/cmd"
)

var Version = "dev"

func main() {
	if err := cmd.Execute(Version); err != nil {
		cmd.ReportError(err)
		os.Exit(1)
	}
}
