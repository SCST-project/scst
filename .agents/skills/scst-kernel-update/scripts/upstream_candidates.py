#!/usr/bin/env python3
"""Report upstream SCST kernel candidates without sourcing or editing config."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

FEED = "https://www.kernel.org/releases.json"
ARCHIVE = "https://cdn.kernel.org/pub/linux/kernel/v{}.x/"
VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
OPTIONS = re.compile(r"(?:-(?:nc|ns|nm|4|f|i|u|p))*")


def version_key(version):
    parts = tuple(map(int, version.split(".")))
    return parts + (0,) * (3 - len(parts))


def series(version):
    return ".".join(version.split(".")[:2])


def read_config(path):
    text = path.read_text()
    match = re.search(r'^ABT_KERNELS="([^"$`]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("expected a literal double-quoted ABT_KERNELS assignment")
    entries = match[1].replace("\\\n", " ").split()
    upstream = {}
    for entry in entries:
        if "^" in entry:
            continue
        match = re.fullmatch(r"(" + VERSION.pattern + r")(" + OPTIONS.pattern + r")", entry)
        if not match:
            raise ValueError(f"unrecognized upstream entry: {entry}")
        version = match[1]
        name = series(version)
        if name in upstream:
            raise ValueError(f"duplicate upstream series: {name}")
        upstream[name] = version
    if not upstream:
        raise ValueError("no upstream versions found")
    return upstream


def fetch(url):
    for attempt in range(2):
        try:
            with urlopen(url, timeout=25) as response:
                return response.read().decode("utf-8")
        except OSError:
            if attempt:
                raise


class Tarballs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.versions = set()

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        name = Path(urlparse(dict(attrs).get("href") or "").path).name
        match = re.fullmatch(r"linux-(" + VERSION.pattern + r")\.tar\.xz", name)
        if match:
            self.versions.add(match[1])


def read_archive(major):
    url = ARCHIVE.format(major)
    parser = Tarballs()
    parser.feed(fetch(url))
    if not parser.versions:
        raise ValueError(f"no release tarballs found: {url}")
    return url, parser.versions


def inventory(current):
    releases = json.loads(fetch(FEED))["releases"]
    published = [r["version"] for r in releases if VERSION.fullmatch(r["version"])]
    if not published:
        raise ValueError("release feed contains no final releases")
    majors = sorted({int(v.split(".")[0]) for v in [*current.values(), *published]})
    latest = {}
    for version in published:
        name = series(version)
        if name not in latest or version_key(version) > version_key(latest[name][0]):
            latest[name] = (version, FEED)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for url, versions in pool.map(read_archive, majors):
            for version in versions:
                name = series(version)
                if name not in latest or version_key(version) >= version_key(latest[name][0]):
                    latest[name] = (version, url)
    updates = []
    for name, old in current.items():
        if name not in latest:
            raise ValueError(f"no published release found for existing series {name}")
        new, source = latest[name]
        if version_key(new) < version_key(old):
            raise ValueError(f"sources are older than configured {old}: {new}")
        if version_key(new) > version_key(old):
            updates.append({"old": old, "new": new, "source": source})
    additions = [{"new": latest[name][0], "source": latest[name][1]}
                 for name in sorted({series(v) for v in published} - current.keys(),
                                    key=version_key, reverse=True)]
    return {"checked_at": datetime.now(timezone.utc).isoformat(),
            "checked_upstream_series": len(current),
            "updates": updates, "new_series_for_review": additions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        result = inventory(read_config(args.config))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
