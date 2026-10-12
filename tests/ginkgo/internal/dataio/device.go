// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"scst-component-tests/internal/testcfg"
)

type Profile struct {
	Handler   string
	ReadOnly  bool
	ExtraLUNs bool
}

type Backend struct {
	Handler, Attributes, Serial string
	Bytes                       uint64
	BlockSize                   uint32
}

type block struct {
	HCTL        string    `json:"hctl"`
	Path        string    `json:"path"`
	Type        string    `json:"type"`
	Size        uint64    `json:"size"`
	Logical     uint32    `json:"log-sec"`
	ReadOnly    bool      `json:"ro"`
	Serial      string    `json:"serial"`
	Filesystem  *string   `json:"fstype"`
	Mountpoints []*string `json:"mountpoints"`
	Children    []block   `json:"children"`
}

func blocks(output string) ([]block, error) {
	var list struct {
		Devices []block `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(output), &list); err != nil {
		return nil, err
	}
	if list.Devices == nil {
		return nil, fmt.Errorf("missing lsblk device list")
	}
	return list.Devices, nil
}

func unused(b block) error {
	if b.Type != "disk" || len(b.Children) != 0 || b.Filesystem != nil && *b.Filesystem != "" {
		return fmt.Errorf("%s must be a plain disk without partitions, holders or filesystem signatures", b.Path)
	}
	for _, mount := range b.Mountpoints {
		if mount != nil && *mount != "" {
			return fmt.Errorf("%s is mounted at %s", b.Path, *mount)
		}
	}
	return nil
}

func listBlocks(ctx context.Context, run RunFunc, timeout time.Duration, path string) ([]block, error) {
	args := []string{"lsblk", "--json", "--bytes", "--tree", "--output", "PATH,TYPE,SIZE,LOG-SEC,RO,MOUNTPOINTS,FSTYPE,SERIAL,HCTL"}
	if path != "" {
		args = append(args, "--", path)
	}
	r, err := run(ctx, timeout, args...)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("lsblk: %s", r.String())
	}
	return blocks(r.Stdout)
}

// PrepareBackend owns only newly created files. The caller records them before
// any fallible operation and removes them only after successful SCST cleanup.
func PrepareBackend(ctx context.Context, cfg testcfg.Config, artifacts, id string, options Profile, run RunFunc, ownFile func(string)) (Backend, error) {
	b := Backend{Handler: options.Handler, Serial: id, Bytes: 16 * 1024 * 1024, BlockSize: 512}
	path := ""
	switch options.Handler {
	case "vdisk_fileio":
		dir := cfg.BackingDir
		if dir == "" {
			dir = artifacts
		}
		f, err := os.CreateTemp(dir, id+"-*.img")
		if err != nil {
			return b, err
		}
		path = f.Name()
		ownFile(path)
		err = f.Truncate(int64(b.Bytes))
		closeErr := f.Close()
		if err != nil {
			return b, err
		}
		if closeErr != nil {
			return b, closeErr
		}
	default:
		return b, fmt.Errorf("unsupported data handler %q", options.Handler)
	}
	if strings.ContainsAny(path, " \t\r\n,;\"{}\\") {
		return b, fmt.Errorf("backing path cannot be represented in scstadmin attributes")
	}
	b.Attributes = fmt.Sprintf("filename=%s,blocksize=%d,thin_provisioned=0,t10_dev_id=%s", path, b.BlockSize, id)
	if options.Handler == "vdisk_fileio" {
		b.Attributes += ",o_direct=0"
	}
	return b, nil
}

// Endpoint addresses only a fixture-owned exported disk, never its backing file.
type Endpoint struct {
	Run                   RunFunc
	Timeout               time.Duration
	Backend               Backend
	ReadOnly              bool
	Artifacts, Name, Path string
}

func (e *Endpoint) Discover(ctx context.Context) error {
	devices, err := listBlocks(ctx, e.Run, e.Timeout, "")
	if err != nil {
		return err
	}
	var matches []block
	var visit func([]block)
	visit = func(list []block) {
		for _, d := range list {
			if d.Serial == e.Backend.Serial && regexp.MustCompile(`^\d+:\d+:\d+:0$`).MatchString(d.HCTL) {
				matches = append(matches, d)
			}
			visit(d.Children)
		}
	}
	visit(devices)
	if len(matches) != 1 {
		return fmt.Errorf("expected one exported disk with serial %s, found %d", e.Backend.Serial, len(matches))
	}
	d := matches[0]
	if err := unused(d); err != nil {
		return err
	}
	if !regexp.MustCompile(`^/dev/[a-zA-Z0-9/_-]+$`).MatchString(d.Path) || d.Size != e.Backend.Bytes || d.Logical != e.Backend.BlockSize || d.ReadOnly != e.ReadOnly {
		return fmt.Errorf("exported device geometry/access mismatch: %+v", d)
	}
	e.Path = d.Path
	if _, err := e.sg(ctx, "sg_turs"); err != nil {
		return err
	}
	return e.Identity(ctx)
}

func (e *Endpoint) Check(ctx context.Context) error {
	path := e.Path
	if err := e.Discover(ctx); err != nil {
		return err
	}
	if path != "" && e.Path != path {
		return fmt.Errorf("exported device path changed from %s to %s", path, e.Path)
	}
	return nil
}

func (e *Endpoint) sg(ctx context.Context, args ...string) ([]byte, error) {
	return success(command(ctx, e.Run, e.Timeout, nil, append(args, e.Path)...))
}

// DeviceID also supplies the vdisk USN, which is limited to 20 characters.
func DeviceID(name string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(name)))[:20] }

func RequireTools(ctx context.Context, run RunFunc, timeout time.Duration) error {
	tools := []string{"python3", "lsblk", "sg_inq", "sg_readcap", "sg_luns", "sg_raw", "sg_turs", "sg_sync"}
	for _, tool := range tools {
		r, err := run(ctx, timeout, tool, "--version")
		if err != nil {
			return err
		}
		if r.ExitCode != 0 {
			return fmt.Errorf("required tool %s: %s", tool, r.String())
		}
	}
	return nil
}
