#!/usr/bin/env python3
"""Download a public raw log dataset and leave it ready to replay (ING-1, AGT-6).

`datasets/manifest.yaml` lists public datasets, each tagged with the shoc source
whose OCSF mapping reads it. Nothing is vendored into the repo: the licences
differ per dataset and some forbid redistribution, so this fetches on demand into
a working directory that is not committed.

    python scripts/fetch_dataset.py --list
    python scripts/fetch_dataset.py --source okta
    python scripts/fetch_dataset.py --name cloudtrail-flaws --dir var/datasets
"""

from __future__ import annotations

import argparse
import gzip
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "datasets" / "manifest.yaml"
DEFAULT_DIR = ROOT / "var" / "datasets"
CHUNK = 1 << 20
TREE = "https://api.github.com/repos/{repo}/git/trees/{ref}?recursive=1"
# Large files in a GitHub repo are Git LFS pointers over plain HTTPS; the media
# host serves the real bytes, so a dataset can be fetched without git-lfs.
MEDIA = "https://media.githubusercontent.com/media/{repo}/{ref}/{path}"


def load() -> list[dict[str, Any]]:
    data = yaml.safe_load(MANIFEST.read_text()) or {}
    return list(data.get("datasets") or [])


def select(entries: list[dict[str, Any]], name: str, source: str) -> list[dict[str, Any]]:
    if name:
        return [e for e in entries if e["name"] == name]
    if source:
        return [e for e in entries if e["source"] == source]
    return entries


def download(url: str, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as resp:
        resp.raise_for_status()
        with target.open("wb") as fh:
            for chunk in resp.iter_bytes(CHUNK):
                fh.write(chunk)
    return target


def unpack(path: Path, into: Path) -> None:
    """Leave the records where the file connector can read them."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            zf.extractall(into)
        path.unlink()
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            tf.extractall(into, filter="data")
        path.unlink()
    elif path.suffix == ".gz" and path.suffixes[:-1]:
        # A single gzipped file: the file connector reads .gz directly, but an
        # inner name like events.json.gz is clearer once unpacked.
        out = path.with_suffix("")
        with gzip.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        path.unlink()


def lfs_paths(spec: dict[str, Any]) -> list[str]:
    """Which files in a repo this dataset wants, asked of the repo's tree."""
    url = TREE.format(repo=spec["repo"], ref=spec.get("ref", "main"))
    with httpx.Client(timeout=60.0, follow_redirects=True) as http:
        resp = http.get(url)
        resp.raise_for_status()
        tree = resp.json().get("tree") or []
    include, suffix = spec["include"], spec.get("suffix", "")
    return sorted(
        node["path"]
        for node in tree
        if node.get("type") == "blob" and include in node["path"] and node["path"].endswith(suffix)
    )


def fetch_lfs(entry: dict[str, Any], into: Path) -> None:
    spec = entry["lfs"]
    paths = lfs_paths(spec)
    print(f"  {len(paths)} file(s) from {spec['repo']}")
    for path in paths:
        url = MEDIA.format(repo=spec["repo"], ref=spec.get("ref", "main"), path=path)
        # Flatten: two techniques can hold a file of the same name.
        name = "_".join(path.split("/")[-2:])
        download(url, into / name)


def fetch(entry: dict[str, Any], root: Path) -> Path:
    into = root / entry["name"]
    into.mkdir(parents=True, exist_ok=True)
    if entry.get("lfs"):
        fetch_lfs(entry, into)
    for url in entry.get("urls") or []:
        target = into / url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
        print(f"  {url}")
        download(url, target)
        unpack(target, into)
    return into


def describe(entry: dict[str, Any]) -> str:
    return (
        f"{entry['name']:<28} {entry['source']:<18} {entry.get('size', '?'):<8} "
        f"{entry.get('licence', '?'):<16} {entry.get('what', '')}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="", help="one dataset from the manifest")
    parser.add_argument("--source", default="", help="every dataset for one shoc source")
    parser.add_argument("--dir", default=str(DEFAULT_DIR), help="where to put the files")
    parser.add_argument("--list", action="store_true", help="print the manifest and stop")
    args = parser.parse_args()

    entries = load()
    if args.list:
        for entry in entries:
            print(describe(entry))
        return 0
    chosen = select(entries, args.name, args.source)
    if not chosen:
        print("nothing in the manifest matches; try --list", file=sys.stderr)
        return 1
    root = Path(args.dir)
    for entry in chosen:
        print(f"{entry['name']} ({entry.get('licence', 'licence unknown')})")
        if entry.get("manual"):
            print(f"  not scriptable: {entry['manual']}")
            continue
        into = fetch(entry, root)
        print(f"  -> {into}")
        if entry.get("prepare"):
            print(f"  prepare first: {entry['prepare']}")
        replay = into / entry["replay_subdir"] if entry.get("replay_subdir") else into
        extra = ', "skip_unreadable": true' if entry.get("skip_unreadable") else ""
        print(
            f"  shoc source configure --source file --settings "
            f'\'{{"path": "{replay}", "mapping": "{entry["source"]}", '
            f'"as_recorded": true{extra}}}\''
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
