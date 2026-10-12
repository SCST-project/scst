// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"context"
	"fmt"
)

// RequireEmpty checks whether replacing the loaded SCST stack is safe for this
// test profile. It also accepts a core without scst_local on an initial run.
func (c *Client) RequireEmpty(ctx context.Context) error {
	return c.RequireEmptyDriver(ctx, "scst_local")
}

func (c *Client) RequireEmptyDriver(ctx context.Context, allowed string) error {
	drivers, err := c.Names(ctx, "Driver", "-list_driver")
	if err != nil {
		return err
	}
	for _, driver := range drivers {
		if driver != allowed && driver != "copy_manager" {
			return fmt.Errorf("unexpected target driver %q", driver)
		}
		if driver == allowed {
			targets, err := c.DriverTargets(ctx, driver)
			if err != nil {
				return err
			}
			if len(targets) != 0 {
				return fmt.Errorf("%s targets still exist: %v", driver, targets)
			}
		}
	}
	devices, err := c.Devices(ctx)
	if err != nil {
		return err
	}
	if len(devices) != 0 {
		return fmt.Errorf("SCST devices still exist: %v", devices)
	}
	groups, err := c.Names(ctx, "Device Group", "-list_dgrp")
	if err != nil {
		return err
	}
	if len(groups) != 0 {
		return fmt.Errorf("ALUA device groups still exist: %v", groups)
	}
	return nil
}

func (c *Client) Devices(ctx context.Context) (map[string]string, error) {
	out, err := c.Query(ctx, "-list_device")
	if err != nil {
		return nil, err
	}
	return Pairs(out, "Handler", "Device")
}

func (c *Client) Targets(ctx context.Context) (map[string]string, error) {
	return c.DriverTargets(ctx, "scst_local")
}

func (c *Client) DriverTargets(ctx context.Context, driver string) (map[string]string, error) {
	out, err := c.Query(ctx, "-list_target", "-driver", driver)
	if err != nil {
		return nil, err
	}
	return Pairs(out, "Driver", "Target")
}

func (c *Client) Names(ctx context.Context, heading string, args ...string) ([]string, error) {
	out, err := c.Query(ctx, args...)
	if err != nil {
		return nil, err
	}
	sections, err := NamedSections(out, heading)
	return sections[heading], err
}

func (c *Client) Assignments(ctx context.Context, target string) (Assignments, error) {
	return c.DriverAssignments(ctx, "scst_local", target)
}

func (c *Client) DriverAssignments(ctx context.Context, driver, target string) (Assignments, error) {
	out, err := c.Query(ctx, "-list_group", "-driver", driver, "-target", target)
	if err != nil {
		return Assignments{}, err
	}
	a, err := ParseAssignments(out)
	if err == nil && (a.Driver != driver || a.Target != target) {
		err = fmt.Errorf("unexpected assignment owner %s/%s", a.Driver, a.Target)
	}
	return a, err
}

func (c *Client) SessionDetails(ctx context.Context) (map[string]map[string]Session, error) {
	out, err := c.Query(ctx, "-list_sessions")
	if err != nil {
		return nil, err
	}
	return ParseSessions(out)
}

func (c *Client) Attributes(ctx context.Context, args ...string) (map[string]Attribute, error) {
	out, err := c.Query(ctx, append(args, "-nonkey")...)
	if err != nil {
		return nil, err
	}
	return Attributes(out)
}

func (c *Client) Scalar(ctx context.Context, name string, args ...string) (string, error) {
	attrs, err := c.Attributes(ctx, args...)
	if err != nil {
		return "", err
	}
	a, exists := attrs[name]
	if !exists || len(a.Values) != 1 {
		return "", fmt.Errorf("expected one value for attribute %q, got %+v", name, a)
	}
	return a.Values[0], nil
}

func (c *Client) Sessions(ctx context.Context) (map[string][]string, error) {
	out, err := c.Query(ctx, "-list_sessions")
	if err != nil {
		return nil, err
	}
	return SessionNames(out)
}

func (c *Client) DeviceGroup(ctx context.Context, name string) (map[string][]string, error) {
	out, err := c.Query(ctx, "-list_dgrp", name)
	if err != nil {
		return nil, err
	}
	return NamedSections(out, "Devices", "Target Groups")
}
