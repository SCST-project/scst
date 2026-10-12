// SPDX-License-Identifier: GPL-2.0-only
package initiator

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Portal is the address plus port, excluding the target portal group tag.
type Session struct{ ID, Portal, Target string }

func splitPortal(value string) (string, error) {
	portal, tag, ok := strings.Cut(value, ",")
	if !ok {
		return "", fmt.Errorf("missing portal group tag: %q", value)
	}
	if _, err := strconv.Atoi(tag); err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(portal)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid portal port: %q", value)
	}
	return portal, nil
}

// Sessions parses iscsiadm -m session's default output. Unexpected rows fail
// closed; they must never be interpreted as evidence that cleanup completed.
func Sessions(output string) ([]Session, error) {
	var result []Session
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "tcp:" || !strings.HasPrefix(fields[1], "[") || !strings.HasSuffix(fields[1], "]") || fields[4] != "(non-flash)" {
			return nil, fmt.Errorf("unexpected initiator session row: %q", line)
		}
		id := strings.TrimSuffix(strings.TrimPrefix(fields[1], "["), "]")
		if n, err := strconv.Atoi(id); err != nil || n < 1 {
			return nil, fmt.Errorf("invalid session ID: %q", id)
		}
		portal, err := splitPortal(fields[2])
		if err != nil {
			return nil, err
		}
		result = append(result, Session{id, portal, fields[3]})
	}
	return result, nil
}

func Discovery(output string) (map[string]string, error) {
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("unexpected discovery row: %q", line)
		}
		portal, err := splitPortal(fields[0])
		if err != nil {
			return nil, err
		}
		if _, exists := result[fields[1]]; exists {
			return nil, fmt.Errorf("duplicate discovered target %q", fields[1])
		}
		result[fields[1]] = portal
	}
	return result, nil
}

func Ifaces(output string) ([]string, error) {
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.Contains(fields[1], ",") {
			return nil, fmt.Errorf("unexpected iface row: %q", line)
		}
		names = append(names, fields[0])
	}
	return names, nil
}
