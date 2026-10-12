// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"scst-component-tests/internal/testcfg"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: config-check CONFIG.json")
		os.Exit(2)
	}
	cfg, err := testcfg.Load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
