# SPDX-License-Identifier: GPL-2.0-only
"""Expand source or module labels and configured sets into whole suites."""

from pathlib import Path
import re
import tomllib


DEFAULT_LABEL_CONFIG = Path(__file__).with_name('labels.toml')
LABEL = re.compile(r'[A-Z][A-Z0-9_]*')
SUITE = re.compile(r'scst-[A-Za-z0-9_-]+')


def load_composites(path=DEFAULT_LABEL_CONFIG):
    with path.open('rb') as source:
        definitions = tomllib.load(source)
    result = {}
    for name, entry in definitions.items():
        if not LABEL.fullmatch(name) or name == 'ALL' or not isinstance(entry, dict):
            raise ValueError(f'{path}: invalid composite label {name!r}')
        if entry.keys() - {'description', 'labels', 'suites'}:
            raise ValueError(f'{path}: unknown fields in {name}')
        description = entry.get('description', '')
        if not isinstance(description, str) or '\n' in description or '\r' in description:
            raise ValueError(f'{path}: {name}.description must be a single-line string')
        for field, pattern in (('labels', LABEL), ('suites', SUITE)):
            values = entry.get(field, [])
            if not isinstance(values, list) or any(
                    not isinstance(value, str) or not pattern.fullmatch(value) for value in values):
                raise ValueError(f'{path}: {name}.{field} must be an array of valid names')
        labels, suites = entry.get('labels', []), entry.get('suites', [])
        if not labels and not suites:
            raise ValueError(f'{path}: composite label {name} is empty')
        if invalid := set(labels) & (definitions.keys() | {'ALL'}):
            raise ValueError(f'{path}: {name} must reference base labels only: {sorted(invalid)}')
        result[name] = {'description': description, 'labels': labels, 'suites': suites}
    return result


def expand_labels(suites, selected, composites):
    """Validate requested sets against this inventory and keep its suite order.

    Unselected composites may refer to absent modules. A selected composite
    must resolve completely, rather than silently running only part of it.
    """
    base = set(suites.values())
    if conflicts := base & composites.keys():
        raise ValueError(f'Composite labels conflict with base labels: {sorted(conflicts)}')
    if not selected or ('ALL' in selected and selected != ['ALL']):
        raise ValueError('Select labels or ALL alone')
    if selected == ['ALL']:
        return list(suites)
    if unknown := set(selected) - base - composites.keys():
        raise ValueError(f'Unknown or unavailable KUnit labels: {sorted(unknown)}')
    chosen = set()
    for name in selected:
        if name in base:
            chosen.update(suite for suite, label in suites.items() if label == name)
            continue
        entry = composites[name]
        if missing := set(entry['labels']) - base:
            raise ValueError(f'{name}: base labels absent from this inventory: {sorted(missing)}')
        if missing := set(entry['suites']) - suites.keys():
            raise ValueError(f'{name}: suites absent from this inventory: {sorted(missing)}')
        chosen.update(entry['suites'])
        chosen.update(suite for suite, label in suites.items() if label in entry['labels'])
    if not chosen:
        raise ValueError('Selected labels contain no suites')
    return [suite for suite in suites if suite in chosen]
