// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"scst-component-tests/internal/admin"
)

type RunFunc func(context.Context, time.Duration, ...string) (admin.Result, error)

//go:embed command.py
var binaryCommand string

type Reply struct {
	ExitCode int    `json:"exit_code"`
	Data     []byte `json:"data"`
	Stderr   string `json:"stderr"`
}

func invoke(ctx context.Context, run RunFunc, timeout time.Duration, request any) (Reply, error) {
	var response Reply
	data, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	r, err := run(ctx, timeout, "python3", "-c", binaryCommand, string(data))
	if err != nil {
		return response, fmt.Errorf("data command execution: %w\n%s", err, r.String())
	}
	if r.ExitCode != 0 {
		return response, fmt.Errorf("data command helper: %s", r.String())
	}
	var wire struct {
		ExitCode *int    `json:"exit_code"`
		Data     *[]byte `json:"data"`
		Stderr   *string `json:"stderr"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &wire); err != nil {
		return response, fmt.Errorf("data command response: %w", err)
	}
	if wire.ExitCode == nil || wire.Data == nil || wire.Stderr == nil {
		return response, fmt.Errorf("incomplete data command response")
	}
	response = Reply{*wire.ExitCode, *wire.Data, *wire.Stderr}
	return response, nil
}

func command(ctx context.Context, run RunFunc, timeout time.Duration, input []byte, argv ...string) (Reply, error) {
	return invoke(ctx, run, timeout, struct {
		Args  []string `json:"argv"`
		Input []byte   `json:"input,omitempty"`
	}{argv, input})
}

func success(r Reply, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("data command exit %d: %s", r.ExitCode, r.Stderr)
	}
	return r.Data, nil
}
