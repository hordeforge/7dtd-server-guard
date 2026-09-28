"""Emit a CycloneDX software bill of materials from uv.lock.

`uv.lock` is already the complete, hash-pinned answer to "what is installed", but
it is a resolver's private format: a vulnerability scanner, an auditor, or a
downstream packager cannot read it without uv. This renders the same facts as
CycloneDX 1.6 so the inventory can be attached to a release or fed to a scanner
without the project publishing a package index of its own.

The output is deterministic: the serial number is derived from the lockfile
digest and `metadata.timestamp` is omitted, so regenerating from an unchanged
lock produces a byte-identical file and a diff means the dependency set moved.

Two facts are deliberately absent, because `uv.lock` does not record them:

  licenses   A component carries no `licenses` block. Inventing one from the
             project name would be a compliance claim nobody checked, and a
             wrong license is worse than a missing one. Resolve licenses from
             the sdist in the locked hash set if a release needs them.
  timestamps Component `published` and `modified` are omitted for the same
             reason: the lock stores upload times for hashes, not a release
             history a scanner should treat as provenance.

Usage:
  uv run python tools/sbom.py                       # to stdout
  uv run python tools/sbom.py --out dist/sbom.json  # CycloneDX 1.6 JSON
  uv run python tools/sbom.py --self-test

Exit codes: 0 the bill of materials was written, 1 the lock could not be read
or is not renderable, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib
import uuid
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "uv.lock"
PYPROJECT_PATH = ROOT / "pyproject.toml"

SPEC_VERSION = "1.6"
COMPONENT_TYPE = "library"
# The project itself is the SBOM's root component: a virtual package that uv
# never installs, so it has no purl and never appears in `components`.
ROOT_COMPONENT_TYPE = "application"
# CycloneDX has no field for "installed only for the developer toolchain".
# The distinction is real here (black and mypy run nowhere but this repo's gate),
# so it rides in a namespaced property that any consumer ignores it it does not
# know, rather than being flattened away.
SCOPE_PROPERTY = "cdx:guard:dependency-scope"
RUNTIME_SCOPE = "runtime"
DEV_SCOPE = "dev"
# Deterministic serial number: a version-5 UUID over the lockfile digest, with
# the version and variant bits set, so the value is a valid UUID and the same
# lock always yields the same document.
_UUID_NAMESPACE = uuid.UUID("6f0a2f1c-2c9a-5f6b-9f1d-2f3b4c5d6e7f")

# A lock entry with neither an sdist nor a wheel cannot be installed, so it is
# not an inventory item this project ships.
MIN_HASHES = 1


def _purl(name: str, version: str) -> str:
    """Package URL for a PyPI distribution. The name is lowercased because the
    PyPI index normalizes it that way and two spellings of one project would
    otherwise be two components."""
    return f"pkg:pypi/{name.lower()}@{version}"


def _hashes(entry: dict[str, Any]) -> list[dict[str, str]]:
    """Every sha256 in the lock entry: the sdist first, then wheels in the order
    the lock lists them. The full per-platform set is the integrity record the
    lock actually carries, and dropping the wheels an operator is not using
    would make the SBOM say less than the lock does."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    candidates = [entry.get("sdist")]
    candidates.extend(entry.get("wheels") or [])
    for dist in candidates:
        if not isinstance(dist, dict):
            continue
        alg, _, digest = str(dist.get("hash", "")).partition(":")
        if alg.lower() != "sha256" or not digest or digest in seen:
            continue
        seen.add(digest)
        found.append({"alg": "SHA-256", "content": digest})
    return found


def _package_name(dep: Any) -> str | None:
    """The referenced name from a lock dependency entry, or None if the entry
    is not a named registry package (a path or git source has no version to
    inventory here)."""
    if not isinstance(dep, dict):
        return None
    name = dep.get("name")
    return name if isinstance(name, str) and name else None


def _runtime_roots(lock: dict[str, Any]) -> list[str]:
    """The direct names installed in production.

    The virtual root package's `dependencies` block is what `uv sync` installs
    without `--group dev`. Everything else in the lock is dev toolchain, and a
    package named in both blocks counts as runtime: the production install is
    the one that sets the blast radius of a compromised release.
    """
    runtime: set[str] = set()
    for package in lock.get("package") or []:
        if not isinstance(package, dict):
            continue
        source = package.get("source")
        if not isinstance(source, dict) or "virtual" not in source:
            continue
        for dep in package.get("dependencies") or []:
            name = _package_name(dep)
            if name is not None:
                runtime.add(name)
    return sorted(runtime)


def _reached(entries: dict[str, dict[str, Any]], roots: set[str]) -> set[str]:
    """Every package reachable from `roots` through the lock's dependency
    edges, so a transitive package is inventoried and classified by what pulls
    it in, not by which block it happened to be written in."""
    seen: set[str] = set()
    queue = list(roots)
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        entry = entries.get(name)
        if entry is None:
            continue
        seen.add(name)
        for dep in entry.get("dependencies") or []:
            child = _package_name(dep)
            if child is not None and child not in seen:
                queue.append(child)
    return seen


def build_sbom(lock: dict[str, Any], project_name: str, project_version: str) -> dict[str, Any]:
    """Render a CycloneDX 1.6 document from a parsed uv.lock.

    Raises ValueError with the reason when a locked package cannot be
    inventoried, so a caller never emits a document that quietly omits a
    shipped dependency.
    """
    entries: dict[str, dict[str, Any]] = {}
    for package in lock.get("package") or []:
        if not isinstance(package, dict):
            continue
        # The virtual root and anything not from a registry (a local path
        # dependency) has no version to publish in an inventory.
        source = package.get("source")
        if source is not None and not (isinstance(source, dict) and "registry" in source):
            continue
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("lock entry without a name and version")
        entries[name] = package

    missing = sorted(_referenced_names(lock) - set(entries))
    if missing:
        raise ValueError(f"lock references packages with no registry entry: {', '.join(missing)}")

    runtime_roots = _runtime_roots(lock)
    runtime = _reached(entries, set(runtime_roots))

    root_ref = f"{project_name}@{project_version}"
    components: list[dict[str, Any]] = []
    for name in sorted(entries):
        version = entries[name]["version"]
        digests = _hashes(entries[name])
        if len(digests) < MIN_HASHES:
            raise ValueError(f"lock entry {name} has no sha256 hash to verify against")
        components.append(
            {
                "type": COMPONENT_TYPE,
                "bom-ref": _purl(name, version),
                "name": name,
                "version": version,
                "purl": _purl(name, version),
                "hashes": digests,
                "properties": [
                    {
                        "name": SCOPE_PROPERTY,
                        "value": RUNTIME_SCOPE if name in runtime else DEV_SCOPE,
                    }
                ],
            }
        )

    graph: list[dict[str, Any]] = [
        {
            "ref": root_ref,
            "dependsOn": sorted(
                _purl(n, entries[n]["version"]) for n in runtime_roots if n in entries
            ),
        }
    ]
    graph.extend(
        {"ref": component["bom-ref"], "dependsOn": _refs(entries, entries[component["name"]])}
        for component in components
    )
    graph.sort(key=lambda entry: entry["ref"])

    digest = hashlib.sha256(
        json.dumps(lock, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(_UUID_NAMESPACE, digest.hex())}",
        "version": 1,
        "metadata": {
            "component": {
                "type": ROOT_COMPONENT_TYPE,
                "bom-ref": root_ref,
                "name": project_name,
                "version": project_version,
            },
            "properties": [
                {"name": "cdx:guard:lock-file", "value": LOCK_PATH.name},
                {"name": "cdx:guard:lock-sha256", "value": digest.hex()},
            ],
        },
        "components": components,
        "dependencies": graph,
    }


def _referenced_names(lock: dict[str, Any]) -> set[str]:
    """Every name some package depends on. A name here with no registry entry
    of its own is a lock that references something it does not describe, which
    is a resolver bug the inventory must not paper over."""
    names: set[str] = set()
    for package in lock.get("package") or []:
        if not isinstance(package, dict):
            continue
        for dep in package.get("dependencies") or []:
            child = _package_name(dep)
            if child is not None:
                names.add(child)
    return names


def _refs(entries: dict[str, dict[str, Any]], package: dict[str, Any]) -> list[str]:
    """Refs for a package's own dependencies, skipping any name with no
    registry entry (a package the lock does not describe cannot be
    referenced)."""
    return sorted(
        _purl(child, entries[child]["version"])
        for child in (_package_name(dep) for dep in package.get("dependencies") or [])
        if child is not None and child in entries and entries[child].get("version")
    )


def load(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path} is not valid TOML: {exc}") from exc


def _project_identity() -> tuple[str, str]:
    try:
        data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read {PYPROJECT_PATH}: {exc}") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"{PYPROJECT_PATH} has no [project] table")
    name, version = project.get("name"), project.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError(f"{PYPROJECT_PATH} [project] needs a name and a version")
    return name, version


def render(lock: dict[str, Any], project_name: str, project_version: str) -> str:
    """The document as canonical JSON: sorted keys, two-space indent, one
    trailing newline, so a regenerated file diffs cleanly."""
    document = build_sbom(lock, project_name, project_version)
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _self_test() -> int:
    """Pin the properties the document exists for: every locked package is
    inventoried, runtime and dev sets are classified by reachability, the
    document is byte-identical across runs, and an uninstallable lock entry is
    refused rather than dropped."""
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    lock = {
        "package": [
            {
                "name": "root",
                "version": "1.0.0",
                "source": {"virtual": "."},
                "dependencies": [{"name": "runtime-dep"}, {"name": "shared"}],
                "dev-dependencies": {"dev": [{"name": "dev-only"}, {"name": "shared"}]},
            },
            {
                "name": "runtime-dep",
                "version": "2.0.0",
                "source": {"registry": "https://pypi.org/simple"},
                "dependencies": [{"name": "transitive"}],
                "sdist": {"hash": "sha256:" + "a" * 64},
            },
            {
                "name": "transitive",
                "version": "3.0.0",
                "source": {"registry": "https://pypi.org/simple"},
                "wheels": [{"hash": "sha256:" + "b" * 64}],
            },
            {
                "name": "dev-only",
                "version": "4.0.0",
                "source": {"registry": "https://pypi.org/simple"},
                "sdist": {"hash": "sha256:" + "c" * 64},
            },
            {
                "name": "shared",
                "version": "5.0.0",
                "source": {"registry": "https://pypi.org/simple"},
                "sdist": {"hash": "sha256:" + "d" * 64},
            },
        ]
    }
    text = render(lock, "proj", "9.9.9")
    document = json.loads(text)

    expect(document["bomFormat"] == "CycloneDX", "bomFormat is not CycloneDX")
    expect(document["specVersion"] == SPEC_VERSION, "specVersion is wrong")
    expect(
        "timestamp" not in document["metadata"], "metadata carries a timestamp, so output drifts"
    )
    expect(render(lock, "proj", "9.9.9") == text, "two renders of one lock differ")

    by_name = {c["name"]: c for c in document["components"]}
    expect(
        sorted(by_name) == ["dev-only", "runtime-dep", "shared", "transitive"],
        f"components are {sorted(by_name)}, not every locked registry package",
    )

    def scope(name: str) -> str | None:
        for prop in by_name.get(name, {}).get("properties", []):
            if prop["name"] == SCOPE_PROPERTY:
                return str(prop["value"])
        return None

    expect(scope("runtime-dep") == RUNTIME_SCOPE, "runtime dependency is not marked runtime")
    expect(
        scope("transitive") == RUNTIME_SCOPE,
        "transitive package is not marked runtime: it is installed in production",
    )
    expect(scope("dev-only") == DEV_SCOPE, "dev-group package is not marked dev")
    expect(scope("shared") == RUNTIME_SCOPE, "a package in both groups must count as runtime")

    expect(
        all(c["hashes"] for c in document["components"]),
        "a component ships without a hash, so the integrity record is incomplete",
    )
    expect(
        by_name["runtime-dep"]["purl"] == "pkg:pypi/runtime-dep@2.0.0",
        f"purl is {by_name['runtime-dep']['purl']!r}",
    )
    expect(
        "licenses" not in by_name["runtime-dep"],
        "a license claim was invented; uv.lock records none",
    )
    expect("root" not in by_name, "the virtual root package was inventoried as a dependency")

    graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
    expect(
        graph["proj@9.9.9"] == ["pkg:pypi/runtime-dep@2.0.0", "pkg:pypi/shared@5.0.0"],
        f"root dependsOn is {graph['proj@9.9.9']}, not the runtime root's dependencies",
    )
    expect(
        graph["pkg:pypi/runtime-dep@2.0.0"] == ["pkg:pypi/transitive@3.0.0"],
        f"the dependency graph lost an edge: {json.dumps(graph, sort_keys=True)}",
    )

    # A package that cannot be installed cannot be inventoried, and silently
    # dropping it would understate the release.
    unhashed = json.loads(json.dumps(lock))
    unhashed["package"][1].pop("sdist")
    try:
        render(unhashed, "proj", "9.9.9")
    except ValueError:
        pass
    else:
        failures.append("a locked package with no hash rendered instead of raising")

    dangling = json.loads(json.dumps(lock))
    dangling["package"][0]["dependencies"].append({"name": "not-in-lock"})
    try:
        render(dangling, "proj", "9.9.9")
    except ValueError:
        pass
    else:
        failures.append("a dependency with no registry entry rendered instead of raising")

    if failures:
        print("sbom: self-test FAILED", file=sys.stderr)
        for item in failures:
            print("  " + item, file=sys.stderr)
        return 1
    print("sbom: self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="write the document here instead of stdout; parent directories are created",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in assertions and exit, reading no lockfile",
    )
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    try:
        name, version = _project_identity()
        text = render(load(LOCK_PATH), name, version)
    except ValueError as exc:
        print(f"sbom: {exc}", file=sys.stderr)
        return 1

    if args.out:
        destination = pathlib.Path(args.out)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"sbom: cannot write {destination}: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
