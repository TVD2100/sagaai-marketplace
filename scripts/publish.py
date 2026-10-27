"""
scripts/publish.py - build the marketplace catalog repository.

Self-contained on purpose: Python 3.9+, the standard library and
``cryptography`` for signing, nothing from the platform. The catalog can be
rebuilt from a fresh clone without SagaAI next to it.

One entity version at a time::

    python scripts/publish.py --type skill --id my_skill --version 1.0.0 \
        --path ./build/my_skill --manifest ./build/my_skill/entity.json \
        --root . --sign-key ~/.sagaai/marketplace.pem

Check a published catalog without changing it::

    python scripts/publish.py --root . --verify-only

``--init-key`` creates the signing pair instead of publishing: the private
half stays outside the repository, the public half goes to
``keys/<key_id>.pub``.
"""
from __future__ import annotations

import argparse
import sys

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

#: Index schema written by :func:`rebuild_index`.
INDEX_SCHEMA = "sagaai.marketplace.index/1"

#: Bundle schema, kept here so the publisher writes one shape.
BUNDLE_SCHEMA = "sagaai.marketplace.bundle/1"

#: Catalog folders are plural (``skills/``) while entity types are singular.
TYPE_FOLDERS = {
    "agent": "agents",
    "skill": "skills",
    "rag": "rag",
    "mcp": "mcp",
}

#: Fixed timestamp of every archive member (1980-01-01, the zip epoch).
_ARCHIVE_MTIME = 315532800

#: Semver, without the build part the platform never compares.
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")

#: Charset a catalog id may use; the id reaches a filesystem path.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

#: Paths a package must not contain, mirroring the installer's checks.
_UNSAFE_PARTS = ("..",)


class PublishError(Exception):
    """Raised when a catalog cannot be built from the given folder.

    Carries ``code``, ``message`` and ``details`` so the CLI and the platform
    can report a refusal without parsing the text.
    """

    def __init__(self, code: str, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.code = str(code or "publish_failed")
        self.message = str(message or "")
        self.details = details or {}


# ─── Helpers ──────────────────────────────────────────────────────────────

def type_folder(type_: str) -> str:
    """Return the catalog folder name of an entity type."""
    return TYPE_FOLDERS.get(str(type_ or "").strip(), str(type_ or "").strip())


def _now_iso() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(data: bytes) -> str:
    """Return the hex sha256 of *data*."""
    return hashlib.sha256(data).hexdigest()


def canonical_json(payload) -> bytes:
    """Return the canonical JSON encoding of *payload*.

    Sorted keys, no insignificant whitespace, UTF-8 without ASCII escaping.
    A signature is computed over exactly these bytes, so the platform must be
    able to reproduce them from the parsed document - which is why the
    encoding is fixed here instead of using ``json.dumps`` defaults.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _check_id(value: str, field: str) -> str:
    """Return a validated catalog id or raise."""
    text = str(value or "").strip()
    if not _ID_RE.match(text):
        raise PublishError(
            "invalid_id",
            f"{field} '{text or '-'}' must be lowercase [a-z0-9_-], up to 64 chars",
            {"field": field, "value": text},
        )
    return text


def _check_version(value: str) -> str:
    """Return a validated semver or raise."""
    text = str(value or "").strip()
    if not _SEMVER_RE.match(text):
        raise PublishError(
            "invalid_version",
            f"Version '{text or '-'}' is not valid semver",
            {"version": text},
        )
    return text


# ─── Deterministic package ────────────────────────────────────────────────

def collect_files(folder: str) -> Dict[str, bytes]:
    """Return ``{relative path: bytes}`` for every file under *folder*.

    Hidden files and ``__pycache__`` are skipped: they are never part of a
    package and would make the archive differ between two machines. Unsafe
    names are refused here, before anything is written anywhere.
    """
    root = os.path.abspath(folder)
    if not os.path.isdir(root):
        raise PublishError(
            "folder_missing", f"Entity folder not found: {folder}", {"folder": folder}
        )
    result: Dict[str, bytes] = {}
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not d.startswith("."))
        for name in sorted(names):
            if name.startswith("."):
                continue
            full = os.path.join(current, name)
            rel_path = os.path.relpath(full, root).replace(os.sep, "/")
            if any(part in _UNSAFE_PARTS for part in rel_path.split("/")):
                raise PublishError(
                    "unsafe_path",
                    f"Package path escapes the entity folder: {rel_path}",
                    {"path": rel_path},
                )
            if "\\" in rel_path or any(ord(ch) < 32 for ch in rel_path):
                raise PublishError(
                    "unsafe_path",
                    f"Package path contains a forbidden character: {rel_path!r}",
                    {"path": rel_path},
                )
            with open(full, "rb") as handle:
                result[rel_path] = handle.read()
    if not result:
        raise PublishError(
            "empty_folder", f"Entity folder holds no files: {folder}", {"folder": folder}
        )
    return result


def build_package(files: Dict[str, bytes]) -> bytes:
    """Build a deterministic ``tar.gz`` from ``{relative path: bytes}``.

    Every member gets the same mtime, owner and mode, and the gzip stream is
    written with ``mtime=0``, so two runs over the same files produce the
    same bytes and therefore the same sha256.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for rel_path in sorted(files):
            payload = files[rel_path]
            info = tarfile.TarInfo(name=rel_path)
            info.size = len(payload)
            info.mtime = _ARCHIVE_MTIME
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return packed.getvalue()


# ─── Entity manifest ──────────────────────────────────────────────────────

def build_manifest(
    entity: dict,
    files: Dict[str, bytes],
    package_url: str,
) -> Tuple[dict, bytes]:
    """Return ``(manifest, package bytes)`` with every hash filled in.

    The caller supplies the descriptive part of the manifest (name,
    description, licence, preset, ...). Everything that must match the bytes
    on disk - ``files``, ``package.sha256``, ``package.size`` - is computed
    here and overwrites whatever the input carried, because a manifest whose
    hashes disagree with its package is the one failure the platform cannot
    recover from.
    """
    entity_id = _check_id(entity.get("id"), "id")
    version = _check_version(entity.get("version"))
    type_ = str(entity.get("type") or "skill").strip()
    if type_ not in TYPE_FOLDERS:
        raise PublishError(
            "invalid_type",
            f"Unknown entity type '{type_}'",
            {"type": type_, "known": sorted(TYPE_FOLDERS)},
        )
    package = build_package(files)
    manifest = {key: value for key, value in entity.items() if key != "files"}
    manifest.update({
        "schema": str(entity.get("schema") or "sagaai.marketplace.entity/1"),
        "type": type_,
        "id": entity_id,
        "version": version,
        "files": {path: sha256_bytes(payload) for path, payload in sorted(files.items())},
        "package": {
            **(entity.get("package") if isinstance(entity.get("package"), dict) else {}),
            "url": package_url,
            "sha256": sha256_bytes(package),
            "size": len(package),
        },
    })
    return manifest, package


# ─── Repository layout ────────────────────────────────────────────────────

def version_dir(root: str, type_: str, entity_id: str, version: str) -> str:
    """Return ``<root>/<type folder>/<id>/<version>``.

    The version sits directly under the entity folder, next to ``latest/``:
    that is the layout the platform transport resolves, and keeping the two
    in step matters more than a deeper tree.
    """
    return os.path.join(
        root, type_folder(type_), entity_id, version
    )


def _write_json(path: str, payload: dict) -> None:
    """Write JSON with a trailing newline, creating the parent folder."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def publish_entity(
    root: str,
    entity_folder: Optional[str],
    manifest: dict,
    *,
    package_name: str = "package.tar.gz",
) -> dict:
    """Publish one version of an entity into a catalog tree.

    The package and its manifest are written once, into the versioned folder;
    ``latest/entity.json`` is then refreshed to point at the newest version.
    Publishing the same version twice with the same content is a no-op, and
    with different content it is refused: a published version never changes
    under a client that pinned it.

    *entity_folder* may be ``None`` for an entity that ships no files (an MCP
    server is a preset, nothing else): its manifest then carries neither
    ``files`` nor ``package``, which is exactly what the installer expects -
    a package block the catalog cannot serve would be a promise it breaks.

    Returns a report with ``type``, ``id``, ``version``, ``path``,
    ``package_sha256`` and ``changed``.
    """
    entity_id = _check_id(manifest.get("id"), "id")
    version = _check_version(manifest.get("version"))
    type_ = str(manifest.get("type") or "skill").strip()
    folder_name = type_folder(type_)

    target = version_dir(root, type_, entity_id, version)
    manifest_path = os.path.join(target, "entity.json")
    if entity_folder is None and type_ != "mcp":
        raise PublishError(
            "folder_required",
            f"An entity of type '{type_}' ships files and needs a folder",
            {"type": type_, "id": entity_id},
        )

    package = b""
    if entity_folder is None:
        full = {key: value for key, value in manifest.items()
                if key not in ("files", "package")}
        full.update({
            "schema": str(manifest.get("schema") or "sagaai.marketplace.entity/1"),
            "type": type_,
            "id": entity_id,
            "version": version,
        })
    else:
        files = collect_files(entity_folder)
        package_url = f"{folder_name}/{entity_id}/{version}/{package_name}"
        full, package = build_manifest(manifest, files, package_url)

    package_path = os.path.join(target, package_name)
    changed = True
    if os.path.isfile(manifest_path):
        existing_manifest = _read_json(manifest_path)
        existing_package = b""
        if os.path.isfile(package_path):
            with open(package_path, "rb") as handle:
                existing_package = handle.read()
        if existing_manifest is not None and existing_manifest == full and existing_package == package:
            changed = False
        else:
            raise PublishError(
                "version_exists",
                f"Version {version} of '{entity_id}' is already published with other content",
                {"id": entity_id, "version": version},
            )
    if changed:
        os.makedirs(target, exist_ok=True)
        if package:
            with open(package_path, "wb") as handle:
                handle.write(package)
        _write_json(manifest_path, full)

    _refresh_latest(root, type_, entity_id)
    return {
        "ok": True,
        "type": type_,
        "id": entity_id,
        "version": version,
        "path": os.path.relpath(manifest_path, root).replace(os.sep, "/"),
        "package_sha256": str((full.get("package") or {}).get("sha256") or ""),
        "file_count": len(full.get("files") or {}),
        "changed": changed,
    }


def list_versions(root: str, type_: str, entity_id: str) -> List[str]:
    """Return the published versions of one entity, newest first."""
    folder = os.path.join(root, type_folder(type_), entity_id)
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    versions = [name for name in names if _SEMVER_RE.match(name)]
    return sorted(versions, key=_version_key, reverse=True)


def _version_key(version: str) -> tuple:
    """Return a sortable key of a semver string (pre-release sorts lower)."""
    core, _sep, pre = version.partition("-")
    parts = tuple(int(part) for part in core.split(".") if part.isdigit())
    return (parts, 0 if pre else 1, pre)


def _refresh_latest(root: str, type_: str, entity_id: str) -> Optional[str]:
    """Point ``<type>/<id>/latest/entity.json`` at the newest version."""
    versions = list_versions(root, type_, entity_id)
    if not versions:
        return None
    newest = versions[0]
    source_path = os.path.join(
        version_dir(root, type_, entity_id, newest), "entity.json"
    )
    try:
        with open(source_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    latest_path = os.path.join(
        root, type_folder(type_), entity_id, "latest", "entity.json"
    )
    _write_json(latest_path, payload)
    return newest


# ─── Index ────────────────────────────────────────────────────────────────

def _read_json(path: str) -> Optional[dict]:
    """Read a JSON object, or None when the file is missing or broken."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _index_entry(entity: dict) -> dict:
    """Return the index summary of one entity manifest."""
    type_ = str(entity.get("type") or "skill")
    entity_id = str(entity.get("id") or "")
    version = str(entity.get("version") or "")
    entry = {
        "type": type_,
        "id": entity_id,
        "version": version,
        "name": entity.get("name"),
        "description": entity.get("description"),
        "path": f"{type_folder(type_)}/{entity_id}/{version}",
    }
    for key in ("author", "tags", "icon", "license"):
        if entity.get(key):
            entry[key] = entity[key]
    platform = entity.get("platform") if isinstance(entity.get("platform"), dict) else None
    if platform:
        entry["platform"] = platform
    return entry


def collect_entries(root: str) -> List[dict]:
    """Return index entries for every entity of a catalog tree."""
    entries: List[dict] = []
    for type_ in TYPE_FOLDERS:
        type_dir = os.path.join(root, type_folder(type_))
        try:
            names = sorted(os.listdir(type_dir))
        except OSError:
            continue
        for entity_id in names:
            latest = _read_json(
                os.path.join(type_dir, entity_id, "latest", "entity.json")
            )
            if latest is None:
                continue
            entries.append(_index_entry(latest))
    entries.sort(key=lambda item: (item["type"], item["id"]))
    return entries


def collect_bundles(root: str) -> List[dict]:
    """Return the bundle summaries listed in ``bundles/``."""
    folder = os.path.join(root, "bundles")
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    result: List[dict] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        payload = _read_json(os.path.join(folder, name))
        if payload is None:
            continue
        bundle_id = str(payload.get("id") or name[:-5])
        result.append({
            "id": bundle_id,
            "name": payload.get("name") or bundle_id,
            "path": f"bundles/{name}",
        })
    return result


def rebuild_index(
    root: str,
    *,
    channel: str = "main",
    updated_at: Optional[str] = None,
) -> dict:
    """Rebuild ``index.json`` from the catalog tree and write it back.

    The index is derived, never hand-maintained: it lists the ``latest``
    manifest of every entity plus the bundles present. Writing it last keeps
    a failed publish out of the index entirely.
    """
    index = {
        "schema": INDEX_SCHEMA,
        "channel": str(channel or "main"),
        "updated_at": updated_at or _now_iso(),
        "entities": collect_entries(root),
    }
    bundles = collect_bundles(root)
    if bundles:
        index["bundles"] = bundles
    _write_json(os.path.join(root, "index.json"), index)
    return index


# ─── Signature ────────────────────────────────────────────────────────────

def _load_signing_key(private_key_path: str):
    """Return the Ed25519 private key stored at *private_key_path*."""
    from cryptography.hazmat.primitives import serialization

    try:
        with open(private_key_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise PublishError(
            "key_missing", f"Signing key not found: {private_key_path}", {"path": private_key_path}
        ) from exc
    try:
        return serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise PublishError(
            "invalid_key", f"Signing key is not a readable private key: {exc}", {}
        ) from exc


def generate_keypair(private_key_path: str, public_key_path: str, key_id: str) -> dict:
    """Create an Ed25519 key pair and write both halves to disk.

    The private key is written with owner-only permissions and never leaves
    the publisher's machine; the public key is what ships in ``keys/``.
    Returns ``{"key_id", "public_key", "private_key", "fingerprint"}``.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.makedirs(os.path.dirname(os.path.abspath(private_key_path)), exist_ok=True)
    with open(private_key_path, "wb") as handle:
        handle.write(private_pem)
    try:
        os.chmod(private_key_path, 0o600)
    except OSError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(public_key_path)), exist_ok=True)
    with open(public_key_path, "wb") as handle:
        handle.write(public_pem)
    return {
        "key_id": key_id,
        "public_key": public_key_path,
        "private_key": private_key_path,
        "fingerprint": sha256_bytes(public_pem),
    }


def sign_index(root: str, private_key_path: str, key_id: str) -> dict:
    """Sign ``index.json`` and write ``index.json.sig``.

    The signature covers the canonical JSON of the whole index, so any change
    to any entry invalidates it. Returns the signature record that was
    written.
    """
    index_path = os.path.join(root, "index.json")
    payload = _read_json(index_path)
    if payload is None:
        raise PublishError("index_missing", "index.json is missing or unreadable", {})
    private = _load_signing_key(private_key_path)
    message = canonical_json(payload)
    signature = private.sign(message)
    record = {
        "schema": "sagaai.marketplace.signature/1",
        "algorithm": "ed25519",
        "key_id": str(key_id or ""),
        "index_sha256": sha256_bytes(message),
        "signature": signature.hex(),
        "signed_at": _now_iso(),
    }
    _write_json(os.path.join(root, "index.json.sig"), record)
    return record


def verify_index_signature(root: str, public_key_path: str) -> dict:
    """Check ``index.json.sig`` against ``index.json`` and a public key.

    Returns ``{"ok": bool, "reason": str}``; a missing signature is reported
    as ``signature_missing`` instead of raising, so a caller can decide
    whether an unsigned catalog is acceptable.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    record = _read_json(os.path.join(root, "index.json.sig"))
    payload = _read_json(os.path.join(root, "index.json"))
    if payload is None:
        return {"ok": False, "reason": "index_missing"}
    if record is None:
        return {"ok": False, "reason": "signature_missing"}
    try:
        with open(public_key_path, "rb") as handle:
            raw = handle.read()
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            return {"ok": False, "reason": "key_is_not_ed25519"}
    except Exception as exc:
        return {"ok": False, "reason": f"key_unreadable: {exc}"}
    message = canonical_json(payload)
    digest = sha256_bytes(message)
    if str(record.get("index_sha256") or "") != digest:
        return {"ok": False, "reason": "index_changed"}
    try:
        signature = bytes.fromhex(str(record.get("signature") or ""))
    except ValueError:
        return {"ok": False, "reason": "signature_malformed"}
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return {"ok": False, "reason": "signature_invalid"}
    return {"ok": True, "reason": "verified", "key_id": record.get("key_id")}


# ─── One-call publish ─────────────────────────────────────────────────────

def publish(
    root: str,
    entity_folder: Optional[str],
    manifest: dict,
    *,
    private_key_path: Optional[str] = None,
    key_id: str = "sagaai-marketplace-2026",
    channel: str = "main",
) -> dict:
    """Publish one entity version and refresh (and optionally sign) the index.

    This is the call ``scripts/publish.py`` makes: write the immutable
    version, refresh the pointers, rebuild the index, sign it last.
    """
    report = publish_entity(root, entity_folder, manifest)
    index = rebuild_index(root, channel=channel)
    signature = None
    if private_key_path:
        signature = sign_index(root, private_key_path, key_id)
    verification = None
    if private_key_path:
        public_path = os.path.join(root, "keys", f"{key_id}.pub")
        if os.path.isfile(public_path):
            verification = verify_index_signature(root, public_path)
    report["index_entities"] = len(index.get("entities") or [])
    report["signed"] = bool(signature)
    report["signature_verified"] = bool((verification or {}).get("ok"))
    return report

def _read_manifest(path: str, type_: str, entity_id: str, version: str) -> dict:
    """Return the descriptive manifest with id/type/version filled in.

    A manifest file is optional: an entity whose package is self-describing
    can be published from the command line alone, and the fields that decide
    where the version lands are always taken from the arguments so a stale
    file cannot publish into the wrong folder.
    """
    manifest = {}
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot read manifest {path}: {exc}")
        if not isinstance(loaded, dict):
            raise SystemExit(f"manifest {path} must be a JSON object")
        manifest = loaded
    manifest.update({"type": type_, "id": entity_id, "version": version})
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    """Return the argument parser of the publisher CLI."""
    parser = argparse.ArgumentParser(
        description="Publish one entity version into a SagaAI marketplace catalog"
    )
    parser.add_argument("--root", default=".", help="catalog repository root")
    parser.add_argument("--type", dest="type_", help="agent | skill | rag | mcp")
    parser.add_argument("--id", dest="entity_id", help="catalog id of the entity")
    parser.add_argument("--version", help="semver of the version being published")
    parser.add_argument("--path", help="folder that holds the entity files")
    parser.add_argument("--manifest", default="", help="descriptive entity.json")
    parser.add_argument("--key-id", default="sagaai-marketplace-2026")
    parser.add_argument("--sign-key", default="", help="Ed25519 private key (PEM)")
    parser.add_argument("--channel", default="main", help="channel recorded in the index")
    parser.add_argument("--init-key", action="store_true",
                        help="create the signing pair instead of publishing")
    parser.add_argument("--private-key", default="",
                        help="where --init-key writes the private half")
    parser.add_argument("--verify-only", action="store_true",
                        help="check index.json.sig and exit without changing anything")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def _report_text(report: dict) -> str:
    """Return the human-readable summary of a publish report."""
    state = "written" if report.get("changed") else "already published"
    lines = [
        f"{report['type']}/{report['id']} {report['version']}: {state}",
        f"  package sha256: {report['package_sha256']}",
        f"  files: {report['file_count']}, index entities: {report['index_entities']}",
    ]
    if report.get("signed"):
        verified = "yes" if report.get("signature_verified") else "no"
        lines.append(f"  signed: yes (verified: {verified})")
    else:
        lines.append("  signed: no")
    return "\n".join(lines)


def _run(args) -> int:
    """Execute the action selected by the parsed arguments."""
    root = os.path.abspath(args.root)

    if args.verify_only:
        public_path = os.path.join(root, "keys", f"{args.key_id}.pub")
        check = verify_index_signature(root, public_path)
        print(json.dumps(check, ensure_ascii=False, indent=2))
        return 0 if check.get("ok") else 1

    if args.init_key:
        private_path = args.private_key or os.path.expanduser("~/.sagaai/marketplace.pem")
        public_path = os.path.join(root, "keys", f"{args.key_id}.pub")
        report = generate_keypair(private_path, public_path, args.key_id)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print("Keep the private key out of the repository.", file=sys.stderr)
        return 0

    missing = [
        name for name, value in (
            ("--type", args.type_), ("--id", args.entity_id),
            ("--version", args.version),
        ) if not value
    ]
    # An MCP entity is a preset with no files: it publishes from the manifest
    # alone. Every other type ships a package and needs its folder.
    needs_folder = str(args.type_ or "").strip() != "mcp"
    if needs_folder and not args.path:
        missing.append("--path")
    if missing:
        _build_parser().error("missing required arguments: " + ", ".join(missing))

    manifest = _read_manifest(args.manifest, args.type_, args.entity_id, args.version)
    try:
        report = publish(
            root,
            os.path.abspath(args.path) if args.path else None,
            manifest,
            private_key_path=args.sign_key or None,
            key_id=args.key_id,
            channel=args.channel,
        )
    except PublishError as exc:
        print(f"publish refused ({exc.code}): {exc.message}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else _report_text(report))
    return 0


def main(argv=None) -> int:
    """Run the publisher CLI and return its exit status."""
    return _run(_build_parser().parse_args(argv))

if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-FileCopyrightText: 2026 SagaAI Platform, Deinekin T.V.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
