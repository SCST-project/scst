// SPDX-License-Identifier: GPL-2.0-only
package testrun

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"scst-component-tests/internal/testcfg"
)

// Groups run in order, with a complete teardown between transports.
var Groups = []struct{ Name, Package string }{
	{"local", "./suite"},
	{"iscsi", "./iscsi"},
}

type Selection struct {
	Group string
	Specs int
}

func ReadSelection(directory string) ([]Selection, error) {
	var selected []Selection
	for _, group := range Groups {
		data, err := os.ReadFile(filepath.Join(directory, group.Name+".json"))
		if err != nil {
			return nil, err
		}
		var entry Selection
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
		if entry.Group != group.Name || entry.Specs < 0 {
			return nil, fmt.Errorf("invalid selection for %s", group.Name)
		}
		if entry.Specs > 0 {
			selected = append(selected, entry)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no specs match GINKGO_LABEL and GINKGO_FOCUS")
	}
	return selected, nil
}

// Validate every selected group before starting the first live suite. An
// optional iSCSI section is harmless when only local specs are selected.
func ValidateSelection(cfg testcfg.Config, selected []Selection) error {
	if !cfg.DisposableHost {
		return fmt.Errorf("disposable_host must be true: tests create exports and change SCST configuration")
	}
	for _, group := range selected {
		if group.Group == "iscsi" {
			if cfg.ISCSI == nil {
				return fmt.Errorf("selected iSCSI specs require an iscsi section in GINKGO_CONFIG")
			}
			if !cfg.ISCSI.Initiator.DisposableHost {
				return fmt.Errorf("iscsi.initiator.disposable_host must be true")
			}
		}
	}
	return nil
}
