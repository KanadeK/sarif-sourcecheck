"""Resolve SARIF physical locations inside one explicitly chosen checkout."""

import hashlib
import json
import re
import stat
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit

VIRTUAL_ROOT = "file:///__sarif_checkout__/"


class InputError(ValueError):
    """Report or options cannot be interpreted safely."""


class LocationError(ValueError):
    """A location failed with a stable, value-free reason code."""


def _object(value):
    if not isinstance(value, dict):
        raise InputError("expected an object in the supported SARIF structure")
    return value


def _array(value):
    if not isinstance(value, list):
        raise InputError("expected an array in the supported SARIF structure")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(_value):
    raise InputError("nonfinite JSON number")


def load_report(path, limit=32 * 1024 * 1024):
    if type(limit) is not int or limit < 1:
        raise InputError("report size limit must be positive")
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise InputError("report exceeds size limit")
    try:
        return json.loads(
            data.decode("utf-8-sig"), object_pairs_hook=_unique, parse_constant=_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("invalid UTF-8 JSON report") from exc


def _uri(value):
    if not isinstance(value, str) or not value:
        raise LocationError("invalid_uri")
    # URI paths must use forward slashes and percent-encode whitespace.
    if any(ch.isspace() or ord(ch) < 32 for ch in value) or "\\" in value:
        raise LocationError("invalid_uri")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise LocationError("invalid_uri")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise LocationError("invalid_uri") from exc
    if "?" in value or "#" in value or parts.netloc:
        raise LocationError("nonlocal_uri")
    if parts.scheme not in {"", "file"}:
        raise LocationError("nonlocal_uri")
    return value


class Resolver:
    def __init__(self, root, run, maps):
        self.root = root
        self.bases = _object(run.get("originalUriBaseIds", {}))
        self.artifacts = _array(run.get("artifacts", []))
        self.maps = maps

    def base_uri(self, name, seen=()):
        if not isinstance(name, str) or name in seen or len(seen) >= 32:
            raise LocationError("base_cycle_or_invalid")
        if name in self.maps:
            return self.maps[name]
        if name not in self.bases:
            raise LocationError("unknown_base_id")
        location = _object(self.bases[name])
        value = _uri(location.get("uri"))
        parent = (
            self.base_uri(location["uriBaseId"], (*seen, name))
            if "uriBaseId" in location
            else VIRTUAL_ROOT
        )
        resolved = urljoin(parent, value)
        if not resolved.endswith("/"):
            raise LocationError("base_not_directory")
        return resolved

    def location(self, value):
        location = _object(value)
        descriptor = None
        if "index" in location:
            index = location["index"]
            if type(index) is not int or not 0 <= index < len(self.artifacts):
                raise LocationError("invalid_artifact_index")
            descriptor = _object(self.artifacts[index])
            indexed = _object(descriptor.get("location", {}))
            if "uri" not in indexed:
                raise LocationError("indexed_artifact_has_no_uri")
            indexed_path = self.path(indexed)
            if "uri" in location and self.path(location) != indexed_path:
                raise LocationError("artifact_reference_conflict")
            return indexed_path, descriptor
        return self.path(location), descriptor

    def path(self, location):
        value = _uri(location.get("uri"))
        parent = self.base_uri(location["uriBaseId"]) if "uriBaseId" in location else VIRTUAL_ROOT
        resolved = urlsplit(urljoin(parent, value))
        try:
            decoded = unquote(resolved.path, encoding="utf-8", errors="strict")
        except UnicodeError as exc:
            raise LocationError("invalid_uri_encoding") from exc
        if "\x00" in decoded or "\\" in decoded:
            raise LocationError("unsafe_path")
        if decoded.startswith("/__sarif_checkout__/"):
            tail = decoded[len("/__sarif_checkout__/") :]
            # Windows drive/device/ADS forms have no place in relative paths.
            if any(":" in piece for piece in tail.split("/")):
                raise LocationError("unsafe_path")
            candidate = self.root / tail
        else:
            # Absolute file URIs are accepted only if they point within this checkout.
            if re.match(r"^/[A-Za-z]:/", decoded):
                decoded = decoded[1:]
            without_drive = re.sub(r"^[A-Za-z]:/", "", decoded)
            if ":" in without_drive:
                raise LocationError("unsafe_path")
            candidate = Path(decoded)
            if not candidate.is_absolute():
                raise LocationError("outside_checkout")
        try:
            final = candidate.resolve()
            final.relative_to(self.root)
        except (ValueError, OSError, RuntimeError) as exc:
            raise LocationError("outside_checkout") from exc
        return final


def _physical_locations(run, run_index):
    # Traverse standard containers only, so extension bags and unknown keys
    # cannot be mistaken for locations or leak values through report pointers.
    containers = {
        "results",
        "locations",
        "relatedLocations",
        "codeFlows",
        "threadFlows",
        "threadFlowLocations",
        "location",
        "stacks",
        "frames",
        "graphs",
        "nodes",
        "invocations",
        "toolExecutionNotifications",
        "toolConfigurationNotifications",
    }
    stack = [(run, f"/runs/{run_index}")]
    while stack:
        value, pointer = stack.pop()
        if isinstance(value, dict):
            for key, item in reversed(list(value.items())):
                escaped = key.replace("~", "~0").replace("/", "~1")
                child = f"{pointer}/{escaped}"
                if key == "physicalLocation":
                    yield _object(item), child
                elif key in containers:
                    stack.append((item, child))
        elif isinstance(value, list):
            stack.extend(
                (item, f"{pointer}/{index}") for index, item in reversed(list(enumerate(value)))
            )


def _read_source(path, limit):
    # Checking the resolved path blocks stable symlink escapes. This is not a
    # sandbox against a different process replacing directories during a read.
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise LocationError("not_regular_file")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as exc:
        raise LocationError("missing_or_unreadable_source") from exc
    if len(data) > limit:
        raise LocationError("source_too_large")
    return data


def _region(region, data):
    region = _object(region)
    if not any(key in region for key in ("startLine", "endLine")):
        return
    start = region.get("startLine", 1)
    end = region.get("endLine", start)
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise LocationError("invalid_line_range")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise LocationError("source_encoding_unsupported") from exc
    # SARIF lines are CR, LF, or CRLF separated, not Python splitlines' full
    # set of Unicode separators. A terminal line ending is not an extra line.
    lines = re.split(r"\r\n|\r|\n", text)
    count = len(lines) - int(text.endswith(("\n", "\r"))) if text else 0
    if end > count:
        raise LocationError("line_out_of_range")


def check(report, root, *, base_maps=None, max_source_bytes=16 * 1024 * 1024, receipt_limit=100):
    """Audit physical locations; never execute tools or emit source contents.

    Base mappings override historical CI roots with checkout-relative directories.
    Checks file existence, line ranges and SHA-256 for indexed artifacts.
    """
    if type(max_source_bytes) is not int or max_source_bytes < 1:
        raise InputError("source size limit must be positive")
    if type(receipt_limit) is not int or receipt_limit < 0:
        raise InputError("receipt limit must be nonnegative")
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise InputError("checkout root must be a directory")
    report = _object(report)
    if report.get("version") != "2.1.0":
        raise InputError("only SARIF 2.1.0 is supported")
    maps = {}
    for name, value in (base_maps or {}).items():
        if not isinstance(name, str) or not name or not isinstance(value, str):
            raise InputError("base mappings require nonempty string names and relative paths")
        folder = Path(value)
        if folder.is_absolute() or re.match(r"^[A-Za-z]:", value) or "\\" in value:
            raise InputError("base mapping must be checkout-relative with forward slashes")
        directory = (root / folder).resolve()
        if not directory.is_relative_to(root) or not directory.is_dir():
            raise InputError("base mapping must name an existing directory inside checkout")
        relative = directory.relative_to(root).as_posix()
        maps[name] = VIRTUAL_ROOT + (quote(relative, safe="/") + "/" if relative != "." else "")
    receipts, codes = [], {}
    total = failed = hashes_checked = 0
    for run_index, run in enumerate(_array(report.get("runs"))):
        resolver = Resolver(root, _object(run), maps)
        for physical, pointer in _physical_locations(run, run_index):
            total += 1
            receipt = {"pointer": pointer}
            try:
                path, descriptor = resolver.location(physical.get("artifactLocation", {}))
                receipt["path"] = path.relative_to(root).as_posix()
                data = _read_source(path, max_source_bytes)
                _region(physical.get("region", {}), data)
                if descriptor and "sha-256" in _object(descriptor.get("hashes", {})):
                    expected = descriptor["hashes"]["sha-256"]
                    if not isinstance(expected, str) or not re.fullmatch(
                        r"[a-fA-F0-9]{64}", expected
                    ):
                        raise LocationError("invalid_sha256")
                    hashes_checked += 1
                    if hashlib.sha256(data).hexdigest() != expected.lower():
                        raise LocationError("sha256_mismatch")
                code = "resolved"
            except LocationError as exc:
                code = str(exc)
                failed += 1
            receipt["code"] = code
            codes[code] = codes.get(code, 0) + 1
            if len(receipts) < receipt_limit:
                receipts.append(receipt)
    if total == 0:
        failed = 1
        codes["no_physical_locations"] = 1
    return {
        "schema_version": 1,
        "passed": failed == 0,
        "locations_checked": total,
        "locations_failed": failed,
        "sha256_checked": hashes_checked,
        "codes": dict(sorted(codes.items())),
        "receipts": receipts,
        "receipts_truncated": total > len(receipts),
        "scope": "physical locations outside extension bags; line ranges; indexed SHA-256",
    }
