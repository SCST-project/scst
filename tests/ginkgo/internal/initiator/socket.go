// SPDX-License-Identifier: GPL-2.0-only
package initiator

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TCPConnection parses ss -Hnt4 state established. With a single state and
// protocol selected, ss omits the State and Netid columns. Require exactly one
// connection to the fixture portal before constructing an exact reset filter.
func TCPConnection(output, portal string) (string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		return "", fmt.Errorf("expected one TCP connection, got %d", len(lines))
	}
	f := strings.Fields(lines[0])
	if len(f) != 4 || f[3] != portal {
		return "", fmt.Errorf("unexpected ss connection: %q", output)
	}
	for _, queue := range f[:2] {
		if _, err := strconv.ParseUint(queue, 10, 64); err != nil {
			return "", fmt.Errorf("invalid ss queue: %q", queue)
		}
	}
	host, port, err := net.SplitHostPort(f[2])
	if err != nil || net.ParseIP(host).To4() == nil || net.ParseIP(host).IsUnspecified() {
		return "", fmt.Errorf("invalid local IPv4 endpoint: %q", f[2])
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid local TCP port: %q", port)
	}
	return f[2], nil
}
