// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The CLI has human-readable tables, not JSON. These parsers recognize their
// structure and reject unknown output instead of turning parse failures into
// an empty object list. Ordering and column padding are not significant.
func body(output string) ([]string, error) {
	var lines []string
	finished := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if finished {
			return nil, fmt.Errorf("unexpected output after CLI footer: %q", line)
		}
		if line == "All done." {
			finished = true
			continue
		}
		if line == "Collecting current configuration: done." {
			continue
		}
		if strings.Trim(line, "-") == "" {
			continue
		}
		lines = append(lines, line)
	}
	if !finished {
		return nil, fmt.Errorf("missing scstadmin completion footer")
	}
	return lines, nil
}

func NamedSections(output string, headings ...string) (map[string][]string, error) {
	lines, err := body(output)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string)
	current := ""
	for _, line := range lines {
		isHeading := false
		for _, heading := range headings {
			if line == heading {
				if _, exists := result[heading]; exists {
					return nil, fmt.Errorf("duplicate heading %q", heading)
				}
				result[heading] = []string{}
				current, isHeading = heading, true
				break
			}
		}
		if isHeading {
			continue
		}
		if current == "" || len(strings.Fields(line)) != 1 {
			return nil, fmt.Errorf("unexpected list row: %q", line)
		}
		result[current] = append(result[current], line)
	}
	for _, heading := range headings {
		if _, exists := result[heading]; !exists {
			return nil, fmt.Errorf("missing heading %q", heading)
		}
	}
	return result, nil
}

// Pairs decodes the Handler/Device and Driver/Target tables. A blank first
// column repeats the previous owner. Empty handler rows use a '-' placeholder.
func Pairs(output, first, second string) (map[string]string, error) {
	lines, err := body(output)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 || strings.Join(strings.Fields(lines[0]), " ") != first+" "+second {
		return nil, fmt.Errorf("missing %s/%s table", first, second)
	}
	result := make(map[string]string)
	owner := ""
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			owner = fields[0]
		} else if len(fields) != 1 || owner == "" {
			return nil, fmt.Errorf("invalid %s/%s row: %q", first, second, line)
		}
		name := fields[len(fields)-1]
		if name == "-" {
			continue
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate %s %q", second, name)
		}
		result[name] = owner
	}
	return result, nil
}

type Attribute struct {
	Values   []string
	Writable bool
	Key      bool
}

var columns = regexp.MustCompile(`[\t ]{2,}`)
var attributeName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Attributes(output string) (map[string]Attribute, error) {
	lines, err := body(output)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 || strings.Join(strings.Fields(lines[0]), " ") != "Attribute Value Writable KEY" {
		return nil, fmt.Errorf("missing attribute table")
	}
	result := make(map[string]Attribute)
	previous := ""
	appendix := ""
	appendixRows := 0
	seenAppendices := make(map[string]bool)
	for _, line := range lines[1:] {
		switch line {
		case "LUN CREATE attributes available", "Initiator CREATE attributes available",
			"Device CREATE attributes available", "Target CREATE attributes available:",
			"Dynamic attributes available":
			if (appendix != "" && appendixRows == 0) || seenAppendices[line] {
				return nil, fmt.Errorf("empty or duplicate attribute appendix: %q", line)
			}
			appendix, appendixRows = line, 0
			seenAppendices[line] = true
			continue
		}
		// Target/group listings append names of supported create parameters.
		// These are capability descriptions, not current attribute values.
		if appendix != "" {
			if !attributeName.MatchString(line) {
				return nil, fmt.Errorf("invalid row in %s: %q", appendix, line)
			}
			appendixRows++
			continue
		}
		// The remaining lines document accepted trace_level values; they are
		// not attributes. This optional appendix follows the complete table.
		if line == "Possible trace levels:" {
			if _, ok := result["trace_level"]; !ok {
				return nil, fmt.Errorf("trace-level help without an attribute")
			}
			break
		}
		if line == "(none)" && len(lines) == 2 {
			return result, nil
		}
		fields := columns.Split(line, -1)
		if len(fields) == 3 && previous != "" {
			fields = append([]string{previous}, fields...)
		} else if len(fields) != 4 {
			return nil, fmt.Errorf("invalid attribute row: %q", line)
		}
		if (fields[2] != "Yes" && fields[2] != "No") || (fields[3] != "Yes" && fields[3] != "No") {
			return nil, fmt.Errorf("invalid attribute flags: %q", line)
		}
		a := result[fields[0]]
		a.Values = append(a.Values, fields[1])
		a.Writable, a.Key = fields[2] == "Yes", fields[3] == "Yes"
		result[fields[0]], previous = a, fields[0]
	}
	if appendix != "" && appendixRows == 0 {
		return nil, fmt.Errorf("empty attribute appendix: %q", appendix)
	}
	return result, nil
}

type Group struct {
	LUNs       map[int]string
	Initiators []string
}

type Assignments struct {
	Driver string
	Target string
	LUNs   map[int]string
	Groups map[string]*Group
}

func ParseAssignments(output string) (Assignments, error) {
	r := Assignments{LUNs: map[int]string{}, Groups: map[string]*Group{}}
	lines, err := body(output)
	if err != nil {
		return r, err
	}
	luns := r.LUNs
	var group *Group
	section := ""
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "Driver: "):
			if r.Driver != "" {
				return r, fmt.Errorf("expected exactly one target")
			}
			r.Driver = strings.TrimPrefix(line, "Driver: ")
		case strings.HasPrefix(line, "Target: "):
			if r.Target != "" {
				return r, fmt.Errorf("expected exactly one target")
			}
			r.Target = strings.TrimPrefix(line, "Target: ")
		case strings.HasPrefix(line, "Group: "):
			name := strings.TrimPrefix(line, "Group: ")
			if _, exists := r.Groups[name]; exists {
				return r, fmt.Errorf("duplicate group %q", name)
			}
			group = &Group{LUNs: map[int]string{}, Initiators: []string{}}
			r.Groups[name], luns, section = group, group.LUNs, ""
		case line == "Assigned LUNs:":
			section = "luns"
		case line == "Assigned Initiators:":
			section = "initiators"
		case line == "(none)" || strings.Join(strings.Fields(line), " ") == "LUN Device" || line == "Initiator":
			if section == "" {
				return r, fmt.Errorf("table data without a section: %q", line)
			}
		case line == fmt.Sprintf("Driver/target '%s/%s' has no associated LUNs.", r.Driver, r.Target):
			section = ""
		case strings.HasPrefix(line, "Group '") && strings.HasSuffix(line, "' has no associated LUNs or initiators."):
			name := strings.TrimSuffix(strings.TrimPrefix(line, "Group '"), "' has no associated LUNs or initiators.")
			if r.Groups[name] != group || group == nil {
				return r, fmt.Errorf("unexpected empty group: %q", line)
			}
			section = ""
		default:
			fields := strings.Fields(line)
			if section == "luns" && len(fields) == 2 {
				n, err := strconv.Atoi(fields[0])
				if err != nil || n < 0 {
					return r, fmt.Errorf("invalid LUN: %q", line)
				}
				if _, exists := luns[n]; exists {
					return r, fmt.Errorf("duplicate LUN: %q", line)
				}
				luns[n] = fields[1]
			} else if section == "initiators" && group != nil && len(fields) == 1 {
				group.Initiators = append(group.Initiators, line)
			} else {
				return r, fmt.Errorf("unexpected assignment row: %q", line)
			}
		}
	}
	if r.Driver == "" || r.Target == "" {
		return r, fmt.Errorf("missing driver/target in assignment listing")
	}
	return r, nil
}

// Session includes only what scstadmin exposes. LUN rows describe the selected
// initiator group's map; the CLI does not expose per-LUN kernel objects or the
// default group's session map.
type Session struct {
	Attributes map[string]Attribute
	LUNs       map[int]string
}

func ParseSessions(output string) (map[string]map[string]Session, error) {
	lines, err := body(output)
	if err != nil {
		return nil, err
	}
	r := make(map[string]map[string]Session)
	owner, name := "", ""
	var table []string
	flush := func() error {
		if name == "" {
			return nil
		}
		attrs, err := Attributes(strings.Join(table, "\n") + "\nAll done.\n")
		if err != nil {
			return fmt.Errorf("session %s/%s: %w", owner, name, err)
		}
		session := Session{Attributes: attrs, LUNs: map[int]string{}}
		for key, attr := range attrs {
			if !strings.HasPrefix(key, "LUN ") {
				continue
			}
			n, err := strconv.Atoi(strings.TrimPrefix(key, "LUN "))
			if err != nil || n < 0 || len(attr.Values) != 1 || attr.Values[0] == "<not set>" {
				return fmt.Errorf("invalid session LUN %q: %+v", key, attr)
			}
			if _, exists := session.LUNs[n]; exists {
				return fmt.Errorf("duplicate session LUN %d", n)
			}
			session.LUNs[n] = attr.Values[0]
		}
		r[owner][name] = session
		name, table = "", nil
		return nil
	}
	empty := false
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "Driver/Target: "):
			if err := flush(); err != nil {
				return nil, err
			}
			if owner != "" && len(r[owner]) == 0 && !empty {
				return nil, fmt.Errorf("missing sessions for %s", owner)
			}
			owner = strings.TrimPrefix(line, "Driver/Target: ")
			parts := strings.Split(owner, "/")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("invalid session owner %q", owner)
			}
			if _, exists := r[owner]; exists {
				return nil, fmt.Errorf("duplicate session owner %q", owner)
			}
			r[owner], empty = map[string]Session{}, false
		case strings.HasPrefix(line, "Session: "):
			if err := flush(); err != nil {
				return nil, err
			}
			if owner == "" || empty {
				return nil, fmt.Errorf("unexpected session %q", line)
			}
			name = strings.TrimPrefix(line, "Session: ")
			if name == "" {
				return nil, fmt.Errorf("empty session name")
			}
			if _, exists := r[owner][name]; exists {
				return nil, fmt.Errorf("duplicate session %q", name)
			}
		case line == "(no sessions)":
			if owner == "" || name != "" || len(r[owner]) != 0 || empty {
				return nil, fmt.Errorf("unexpected empty session list")
			}
			empty = true
		default:
			if name == "" {
				return nil, fmt.Errorf("unexpected session row %q", line)
			}
			table = append(table, line)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if owner != "" && len(r[owner]) == 0 && !empty {
		return nil, fmt.Errorf("missing sessions for %s", owner)
	}
	return r, nil
}

func SessionNames(output string) (map[string][]string, error) {
	sessions, err := ParseSessions(output)
	if err != nil {
		return nil, err
	}
	names := make(map[string][]string)
	for owner, entries := range sessions {
		names[owner] = []string{}
		for name := range entries {
			names[owner] = append(names[owner], name)
		}
	}
	return names, nil
}
