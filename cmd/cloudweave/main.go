package main

import (
	"os"

	"github.com/vedantparmar12/cloudweave/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(cli.Execute(version, os.Args[1:], os.Stdout, os.Stderr))
}
