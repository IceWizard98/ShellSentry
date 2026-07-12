package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// The `run` subcommand is the ForceCommand entrypoint; assert it stays wired
// with its --config flag so a refactor can't silently drop the CLI surface.
func TestRootCmd_HasRunWithConfigFlag(t *testing.T) {
	root := rootCmd()

	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
		}
	}
	if run == nil {
		t.Fatal("root command missing `run` subcommand")
	}
	if run.Flags().Lookup("config") == nil {
		t.Fatal("`run` subcommand missing --config flag")
	}
}
