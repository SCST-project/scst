// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRequireEmpty(t *testing.T) {
	for _, tc := range []struct {
		name, query, table, errorText string
	}{
		{name: "empty stack"},
		{"core only", "-list_driver", "Driver\n------\ncopy_manager", ""},
		{"foreign driver", "-list_driver", "Driver\n------\niscsi", "unexpected target driver"},
		{"target", "-list_target", "Driver Target\n-------------\nscst_local existing", "targets still exist"},
		{"device", "-list_device", "Handler Device\n--------------\nvdisk_nullio existing", "devices still exist"},
		{"ALUA", "-list_dgrp", "Device Group\n------------\nexisting", "device groups still exist"},
		{"bad output", "-list_device", "unknown output", "missing Handler/Device table"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outputs := map[string]string{
				"-list_driver": output("Driver\n------\nscst_local\ncopy_manager"),
				"-list_target": output("Driver Target\n-------------"),
				"-list_device": output("Handler Device\n--------------\nvdisk_nullio -"),
				"-list_dgrp":   output("Device Group\n------------"),
			}
			if tc.query != "" {
				outputs[tc.query] = output(tc.table)
			}
			if tc.name == "core only" {
				delete(outputs, "-list_target")
			}
			data, err := json.Marshal(outputs)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("SCST_QUERY_TEST_OUTPUTS", string(data))
			c := helperClient(t, "query")
			err = c.RequireEmpty(context.Background())
			if tc.errorText == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("expected %q, got %v", tc.errorText, err)
			}
		})
	}
}
