// SPDX-License-Identifier: GPL-2.0-only
package testrun

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// Shared with scripts/ci/vm.py so guest reports use the expected filter.
//
//go:embed labels.json
var labelSetsJSON []byte

// Named sets alias a whole filter; ordinary Ginkgo expressions pass through.
func resolveLabelFilter(filter string) (string, error) {
	var sets map[string]string
	if err := json.Unmarshal(labelSetsJSON, &sets); err != nil {
		return "", fmt.Errorf("Ginkgo label sets: %w", err)
	}
	if expression, ok := sets[strings.TrimSpace(filter)]; ok {
		if strings.TrimSpace(expression) == "" {
			return "", fmt.Errorf("Ginkgo label set %q is empty", filter)
		}
		return expression, nil
	}
	return filter, nil
}
