// SPDX-License-Identifier: GPL-2.0-only
package testrun

import (
	"testing"

	"github.com/onsi/ginkgo/v2/types"
)

func TestLabelSetSelection(t *testing.T) {
	for _, tc := range []struct {
		filter string
		labels []string
		want   bool
	}{
		{"ci-pr", []string{"local", "basic"}, true},
		{"ci-pr", []string{"iscsi", "scsi", "smoke"}, true},
		{"ci-pr", []string{"iscsi", "stress", "race", "issue-367"}, false},
		{"ci-pr", []string{"local", "stress"}, false},
		{"ci-pr", []string{"local", "user", "manual"}, false},
		{"ci-pr", []string{"local", "basic", "manual"}, false},
		{"ci-pr", []string{"local", "smoke", "manual"}, false},
		{"ci-push", []string{"local", "stress"}, true},
		{" ci-push ", []string{"iscsi", "scsi"}, true},
		{"ci-push", []string{"iscsi", "stress", "race", "issue-367"}, false},
		{"ci-push", []string{"local", "user", "manual"}, false},
		{"", []string{"iscsi", "race"}, true},
		{"", []string{"local", "user", "manual"}, true},
		{"user && manual", []string{"local", "user", "manual"}, true},
		{"user && manual", []string{"local", "user", "negative", "smoke"}, false},
		{"iscsi && race", []string{"iscsi", "race"}, true},
		{"iscsi && race", []string{"local", "stress"}, false},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			expression, err := resolveLabelFilter(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			matches, err := types.ParseLabelFilter(expression)
			if err != nil {
				t.Fatal(err)
			}
			if got := matches(tc.labels); got != tc.want {
				t.Fatalf("filter %q (%q) matches %v: got %t, want %t",
					tc.filter, expression, tc.labels, got, tc.want)
			}
		})
	}
}
