// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"scst-component-tests/internal/testcfg"
	"scst-component-tests/internal/testrun"
)

func main() {
	list := flag.Bool("list", false, "list selected specs without host access")
	flag.Parse()
	if err := run(*list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(list bool) error {
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	directory, err := os.MkdirTemp("", "scst-ginkgo-selection-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)

	filters := []string{"-ginkgo.label-filter=" + os.Getenv("GINKGO_LABEL"),
		"-ginkgo.focus=" + os.Getenv("GINKGO_FOCUS")}
	args := []string{"test", "-count=1", "-timeout=0", "-p=1"}
	for _, group := range testrun.Groups {
		args = append(args, group.Package)
	}
	args = append(append(args, "-args"), filters...)
	plan := exec.Command(goTool, args...)
	plan.Env = append(os.Environ(), "SCST_TEST_PLAN_DIR="+directory)
	if output, err := plan.CombinedOutput(); err != nil {
		return fmt.Errorf("discover test selection: %w\n%s", err, output)
	}
	selected, err := testrun.ReadSelection(directory)
	if err != nil {
		return err
	}
	if !list {
		path := os.Getenv("SCST_TEST_CONFIG")
		if path == "" {
			return fmt.Errorf("set GINKGO_CONFIG to a disposable-host JSON file")
		}
		cfg, err := testcfg.Load(path)
		if err != nil {
			return err
		}
		if err := testrun.ValidateSelection(cfg, selected); err != nil {
			return err
		}
	}
	for _, selection := range selected {
		for _, group := range testrun.Groups {
			if group.Name != selection.Group {
				continue
			}
			fmt.Printf("Selected %s: %d specs\n", group.Name, selection.Specs)
			args := []string{"test", "-count=1", "-timeout=0", "-v", group.Package,
				"-args", "-ginkgo.v", "-ginkgo.fail-on-empty"}
			if list {
				args = append(args, "-ginkgo.dry-run")
			}
			command := exec.Command(goTool, append(args, filters...)...)
			command.Env = append(os.Environ(), "SCST_TEST_PLAN_DIR=")
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if err := command.Run(); err != nil {
				// In particular, never start the next transport after failed cleanup.
				return fmt.Errorf("%s suite failed: %w", group.Name, err)
			}
		}
	}
	return nil
}
