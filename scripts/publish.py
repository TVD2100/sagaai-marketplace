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

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

#: Bytes of the key digest that make up a key id (16 hex characters).
KEY_ID_BYTES = 8

#: Schema of the detached signature record written next to a manifest.
SIGNATURE_SCHEMA = "sagaai.marketplace.signature/1"

#: The only signature algorithm this build knows.
ALGORITHM = "ed25519"

#: Environment variable carrying the private key: PEM text or a file path.
SIGNING_KEY_ENV = "SAGAII_SIGNING_KEY"

#: Suffix of the detached signature file.
SIGNATURE_SUFFIX = ".sig"

#: Channels that must carry a signature (fail-closed).
STABLE_CHANNELS = ("stable",)

#: Channels where an unsigned manifest is accepted with a warning.
WARNING_CHANNELS = ("raw", "dev", "main", "beta")


class SigningError(Exception):
    """Raised when a key cannot be loaded or a signature cannot be written.

    Carries a machine-readable ``code`` so a caller reports the failure
    without parsing the message text.
    """

    def __init__(self, code: str, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.code = str(code or "signing_failed")
        self.message = str(message or "")
        self.details = details or {}


# ─── small helpers ──────────────────────────────────────────────────────

def _now_iso() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_hex(payload: bytes) -> str:
    """Return the hex sha256 of *payload*."""
    return hashlib.sha256(payload).hexdigest()


def canonical_json(payload) -> bytes:
    """Return the canonical JSON encoding of *payload*.

    Kept for verifying signatures written by earlier releases, which
    signed a canonical re-serialisation rather than the shipped bytes. New
    signatures never use it: what is signed is exactly what is downloaded.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def signature_path(payload_path: str) -> str:
    """Return the detached signature path of a manifest file."""
    return str(payload_path) + SIGNATURE_SUFFIX


def _serialization():
    """Import and return the ``cryptography`` serialization module.

    The import is lazy so importing :mod:`core.signing` never fails on a
    machine that has no ``cryptography``: only a signing or verification
    call needs it, and the platform declares it as a required dependency.
    """
    from cryptography.hazmat.primitives import serialization

    return serialization


def _ed25519_private():
    """Return the Ed25519 private key class."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey


def _ed25519_public():
    """Return the Ed25519 public key class."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey


# ─── Key ids ───────────────────────────────────────────────────────────

def public_key_der(public_key) -> bytes:
    """Return the DER encoding (SubjectPublicKeyInfo) of a public key."""
    serialization = _serialization()
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_pem(public_key) -> bytes:
    """Return the PEM encoding of a public key."""
    serialization = _serialization()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_id_from_public(public_key) -> str:
    """Return the key id of a public key: 8 bytes of its DER digest.

    Deriving the identifier from the key itself is what stops one key from
    presenting another key's id: the client recomputes it from the bytes it
    holds and looks the key up by the result.
    """
    return hashlib.sha256(public_key_der(public_key)).hexdigest()[: KEY_ID_BYTES * 2]


def key_id_from_pem(raw: bytes) -> str:
    """Return the key id of a PEM-encoded public key."""
    return key_id_from_public(load_public_key_bytes(raw))


def key_id_of(key) -> str:
    """Return the key id of a private or public key object."""
    public = key.public_key() if hasattr(key, "public_key") else key
    return key_id_from_public(public)


def key_id_of_private(path: Optional[str] = None) -> str:
    """Return the key id of the private key at *path* or in the environment.

    The publisher names ``keys/<key_id>.pub`` after this value, so the file
    name and the key inside it are derived from one source.
    """
    return key_id_of(load_private_key(path))


# ─── Key loading ──────────────────────────────────────────────────────

def load_public_key_bytes(raw: bytes):
    """Return the Ed25519 public key encoded in *raw*, or raise.

    A key of another algorithm is refused rather than accepted: the whole
    trust model rests on the key being Ed25519.
    """
    serialization = _serialization()
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same refusal
        raise SigningError(
            "key_unreadable",
            "Public key is not a readable PEM document",
            {"error": str(exc)},
        ) from exc
    if not isinstance(key, _ed25519_public()):
        raise SigningError(
            "key_not_ed25519",
            "Public key is not an Ed25519 key",
            {"type": type(key).__name__},
        )
    return key


def load_public_key(path: str):
    """Load an Ed25519 public key from *path*, or raise :class:`SigningError`."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SigningError(
            "key_missing", f"Public key not found: {path}", {"path": str(path)}
        ) from exc
    return load_public_key_bytes(raw)


def load_private_key(path: Optional[str] = None, env_var: str = SIGNING_KEY_ENV):
    """Load the Ed25519 private key from *path* or from the environment.

    The environment form accepts either the PEM text itself (what a CI
    secret holds) or a path to the file. Signing without a key is an error:
    a publish run must never fall back to emitting unsigned output.
    """
    serialization = _serialization()
    raw: Optional[bytes] = None
    source = str(path or "").strip()
    if source:
        try:
            with open(source, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            raise SigningError(
                "key_missing", f"Signing key not found: {source}", {"path": source}
            ) from exc
    else:
        value = os.environ.get(env_var, "")
        text = value.strip()
        if not text:
            raise SigningError(
                "key_missing",
                f"No signing key: pass a path or set {env_var}",
                {"env": env_var},
            )
        if "BEGIN" in text:
            raw = text.encode("utf-8")
        else:
            try:
                with open(os.path.expanduser(text), "rb") as handle:
                    raw = handle.read()
            except OSError as exc:
                raise SigningError(
                    "key_missing",
                    f"Signing key not found: {text}",
                    {"path": text, "env": env_var},
                ) from exc
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same refusal
        raise SigningError(
            "key_unreadable",
            "Signing key is not a readable unencrypted PEM private key",
            {"error": str(exc)},
        ) from exc
    if not isinstance(key, _ed25519_private()):
        raise SigningError(
            "key_not_ed25519",
            "Signing key is not an Ed25519 key",
            {"type": type(key).__name__},
        )
    return key


def generate_keypair(private_path: str, public_path: str, key_id: str = "") -> dict:
    """Create an Ed25519 pair, write both halves and return their ids.

    The private half is written with owner-only permissions; nothing here
    checks where the caller puts it, but every tool in this repository
    writes it outside the working tree. *key_id* is accepted for callers
    written against the earlier publisher and ignored: the identifier is
    derived from the key, so it can never disagree with a signature.
    """
    serialization = _serialization()
    private = _ed25519_private().generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key_pem(private.public_key())
    os.makedirs(os.path.dirname(os.path.abspath(private_path)), exist_ok=True)
    with open(private_path, "wb") as handle:
        handle.write(private_pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(public_path)), exist_ok=True)
    with open(public_path, "wb") as handle:
        handle.write(public_pem)
    return {
        "ok": True,
        "key_id": key_id_from_public(private.public_key()),
        "public_key": str(public_path),
        "private_key": str(private_path),
        "fingerprint": sha256_hex(public_pem),
    }


# ─── Keyring ──────────────────────────────────────────────────────────

def keyring_paths(key_dir: str) -> list:
    """Return the public key files of a keyring folder, sorted.

    Both ``.pem`` and ``.pub`` files are read: the repository ships
    ``keys/ed25519-public.pem`` while a catalog may keep ``<key_id>.pub``.
    """
    folder = str(key_dir or "")
    if not folder or not os.path.isdir(folder):
        return []
    names = sorted(os.listdir(folder))
    return [
        os.path.join(folder, name)
        for name in names
        if name.lower().endswith((".pem", ".pub")) and not name.startswith(".")
    ]


def load_keyring(key_dir: str) -> Dict[str, Any]:
    """Return ``{key_id: public key}`` for every key file in *key_dir*.

    A file that cannot be read is skipped rather than fatal: one broken key
    in the folder must not stop the others from being trusted. The count of
    skipped files is available through :func:`keyring_report`.
    """
    ring: Dict[str, Any] = {}
    for path in keyring_paths(key_dir):
        try:
            key = load_public_key(path)
        except SigningError:
            continue
        ring[key_id_from_public(key)] = key
    return ring


def keyring_report(key_dir: str) -> dict:
    """Return which key files are trusted and which could not be read."""
    trusted = []
    skipped = []
    for path in keyring_paths(key_dir):
        try:
            key = load_public_key(path)
        except SigningError as exc:
            skipped.append({"path": path, "reason": exc.code})
            continue
        trusted.append({"path": path, "key_id": key_id_from_public(key)})
    return {"ok": True, "dir": str(key_dir), "trusted": trusted, "skipped": skipped}


# ─── Signing and verification ────────────────────────────────────────

def sign_bytes(payload: bytes, private_key, key_id: Optional[str] = None) -> dict:
    """Sign *payload* and return the detached signature record.

    The signature covers the bytes as they are: a caller that re-serialises
    a document between signing and shipping breaks verification, which is
    the intended behaviour - what is signed must be what is downloaded.
    """
    signature = private_key.sign(payload)
    return {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": ALGORITHM,
        "key_id": str(key_id or key_id_of(private_key)),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signed_sha256": sha256_hex(payload),
        "signed_at": _now_iso(),
    }


def write_json_file(path: str, payload: dict) -> None:
    """Write *payload* as indented JSON with a trailing newline, atomically."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def write_signature(
    payload_path: str,
    private_key_path: Optional[str] = None,
    key_id: Optional[str] = None,
) -> dict:
    """Sign the file at *payload_path* and write ``<payload>.sig``.

    Returns the record written. A missing key raises: a publish step that
    cannot sign must stop, not quietly produce an unsigned release.
    """
    with open(payload_path, "rb") as handle:
        payload = handle.read()
    private_key = load_private_key(private_key_path)
    record = sign_bytes(payload, private_key, key_id=key_id)
    write_json_file(signature_path(payload_path), record)
    return record


def read_signature(path: str) -> Optional[dict]:
    """Read a signature file; None when it is missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _decode_signature(record: dict) -> Optional[bytes]:
    """Decode the base64 signature of a record; None when malformed."""
    text = str(record.get("signature") or "").strip()
    if not text:
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_legacy_signature(record: dict) -> Optional[bytes]:
    """Decode the hex signature of a record written by an earlier release."""
    text = str(record.get("signature") or "").strip()
    if not text:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    return raw or None


def verify_bytes(
    payload: bytes,
    record: Optional[dict],
    keys: Dict[str, Any],
    legacy_document: Optional[dict] = None,
) -> dict:
    """Verify a detached signature over *payload* against a keyring.

    Returns ``{"ok", "key_id", "reason"}``. Reasons:

    ``verified``           the signature matches and the key is trusted;
    ``signature_missing``  there is no signature record at all;
    ``signature_malformed`` the record cannot be parsed or decoded;
    ``unknown_key_id``     the record names a key the keyring does not hold;
    ``signature_invalid``  the bytes do not match the signature.

    An unknown key id is a refusal: accepting it would let anybody publish
    under a key of their own choice.

    A record written by an earlier release carries a hex signature over the
    canonical JSON of the parsed document. *legacy_document* lets such a
    record verify as well, so publishing an update does not invalidate an
    already shipped catalog; new records never take that path.
    """
    if not isinstance(record, dict):
        return {"ok": False, "key_id": None, "reason": "signature_missing"}
    key_id = str(record.get("key_id") or "").strip()
    algorithm = str(record.get("algorithm") or ALGORITHM).strip().lower()
    if algorithm != ALGORITHM:
        return {"ok": False, "key_id": key_id or None, "reason": "signature_malformed"}
    signature = _decode_signature(record)
    message = payload
    if signature is None:
        signature = _decode_legacy_signature(record)
        if signature is None or legacy_document is None:
            return {"ok": False, "key_id": key_id or None, "reason": "signature_malformed"}
        message = canonical_json(legacy_document)
    if not key_id:
        return {"ok": False, "key_id": None, "reason": "signature_malformed"}
    key = (keys or {}).get(key_id)
    if key is None:
        return {"ok": False, "key_id": key_id, "reason": "unknown_key_id"}
    from cryptography.exceptions import InvalidSignature

    try:
        key.verify(signature, message)
    except InvalidSignature:
        return {"ok": False, "key_id": key_id, "reason": "signature_invalid"}
    return {"ok": True, "key_id": key_id, "reason": "verified"}


def verify_file(
    payload_path: str,
    key_dir: Optional[str] = None,
    keys: Optional[Dict[str, Any]] = None,
    signature_file: Optional[str] = None,
) -> dict:
    """Verify the detached signature of a manifest on disk.

    With *keys* the keyring is given directly; otherwise it is loaded from
    *key_dir*. Either way the check is local - no key is ever downloaded.
    """
    path = str(payload_path)
    record = read_signature(signature_file or signature_path(path))
    if record is None:
        return {"ok": False, "key_id": None, "reason": "signature_missing", "path": path}
    ring = keys if keys is not None else load_keyring(key_dir or "")
    try:
        with open(path, "rb") as handle:
            payload = handle.read()
    except OSError:
        return {"ok": False, "key_id": None, "reason": "payload_missing", "path": path}
    legacy_document = None
    if _decode_signature(record) is None:
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        legacy_document = parsed if isinstance(parsed, dict) else None
    result = verify_bytes(payload, record, ring, legacy_document=legacy_document)
    result["path"] = path
    declared = str(record.get("signed_sha256") or "")
    if result["ok"] and declared and declared != sha256_hex(payload):
        # The signature already covers the bytes; this extra check only makes
        # a hand-edited record say so instead of failing on the key check.
        result = {"ok": False, "key_id": result.get("key_id"), "reason": "signature_invalid", "path": path}
    return result


# ─── Channel policy ─────────────────────────────────────────────────────

def channel_name(channel: Optional[str]) -> str:
    """Return the bare channel name of a channel URL or name.

    A channel may be given as a URL (``https://host/TVD2100/repo/main``) or
    as a name (``stable``); only the trailing segment decides the policy.
    """
    text = str(channel or "").strip().rstrip("/")
    if not text:
        return "stable"
    if "://" in text or os.sep in text:
        return text.rsplit("/", 1)[-1].strip() or "stable"
    return text


def channel_policy(channel: Optional[str], require_signature: bool = False) -> dict:
    """Return how a channel treats an unsigned manifest.

    ``enforced`` means a missing or invalid signature is a refusal. The
    explicit setting wins: a user who turned signatures on keeps them on for
    a development channel as well.
    """
    name = channel_name(channel)
    enforced = bool(require_signature) or name in STABLE_CHANNELS
    return {
        "channel": name,
        "enforced": enforced,
        "warn": not enforced,
        "mode": "require" if enforced else "warn",
        "reason": (
            "signature required on the stable channel"
            if name in STABLE_CHANNELS
            else ("signature required by the marketplace setting" if require_signature
                  else "unsigned manifests are accepted with a warning")
        ),
    }


def policy_for(channel: Optional[str], settings: Optional[dict] = None) -> dict:
    """Return the channel policy from marketplace settings (or a plain channel)."""
    settings = settings or {}
    return channel_policy(
        channel or settings.get("channel") or "main",
        bool(settings.get("require_signature")),
    )


# ─── Journal ───────────────────────────────────────────────────────────────

def append_journal(path: str, record: dict) -> bool:
    """Append one JSON line to a journal; False when it could not be written.

    The journal is the durable trace of an accepted-unsigned decision: a
    warning the user dismissed must still be findable afterwards. A failure
    to write it never fails the operation it describes.
    """
    if not path:
        return False
    entry = {"at": _now_iso()}
    entry.update(record or {})
    try:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        return False
    return True

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


#: Agent kinds a publisher may ship. An agent entity is either an
#: orchestrator (an employee bundle) or an assistant (a prompt profile); the
#: installer places each kind in its own folder.
AGENT_KINDS = ("orchestrator", "assistant")


def _check_agent_kind(entity: dict, type_: str) -> None:
    """Refuse an agent manifest whose kind the platform cannot install.

    The check lives in the publisher rather than in the installer alone: a
    catalog that accepts an unknown kind produces an entity every installation
    refuses, and the author learns about it from a user instead of from the
    publish run.
    """
    if type_ != "agent":
        return
    kind = str(entity.get("agent_kind") or "orchestrator").strip()
    if kind not in AGENT_KINDS:
        raise PublishError(
            "invalid_agent_kind",
            f"Unknown agent kind '{kind}'",
            {"agent_kind": kind, "known": list(AGENT_KINDS)},
        )


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
    _check_agent_kind(entity, type_)
    manifest = {key: value for key, value in entity.items() if key != "files"}
    if type_ == "agent":
        # The kind is recorded explicitly: a catalog entry without one looks
        # like an incomplete manifest to any consumer that reads the index.
        manifest["agent_kind"] = str(entity.get("agent_kind") or "orchestrator").strip()
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


def _check_republish(
    target: str,
    manifest_path: str,
    package_path: str,
    extra: Dict[str, bytes],
    full: dict,
    package: bytes,
    entity_id: str,
    version: str,
) -> bool:
    """Return True when the version must be written, refuse a content change.

    Identical bytes are a no-op; the same version with other content is
    refused, because a client that pinned it would receive unreviewed bytes.
    """
    if not os.path.isfile(manifest_path):
        return True
    existing_package = b""
    if os.path.isfile(package_path):
        with open(package_path, "rb") as handle:
            existing_package = handle.read()
    same_extra = True
    for name, payload in extra.items():
        existing_extra = os.path.join(target, name)
        if not os.path.isfile(existing_extra):
            same_extra = False
            break
        with open(existing_extra, "rb") as handle:
            if handle.read() != payload:
                same_extra = False
                break
    if _read_json(manifest_path) == full and existing_package == package and same_extra:
        return False
    raise PublishError(
        "version_exists",
        f"Version {version} of '{entity_id}' is already published with other content",
        {"id": entity_id, "version": version},
    )


def _maybe_sign(path: str, private_key_path: Optional[str]) -> None:
    """Sign *path* when a key is configured; leave it alone otherwise.

    ``publish_entity`` is also called by tooling that only rewrites a tree
    (a rebuild, a migration); such a caller has no key and must not be forced
    to have one. The publishing entry point itself has no such choice.
    """
    if private_key_path or os.environ.get(SIGNING_KEY_ENV, "").strip():
        sign_manifest(path, private_key_path)


def publish_entity(
    root: str,
    entity_folder: Optional[str],
    manifest: dict,
    *,
    package_name: str = "package.tar.gz",
    extra_files: Optional[Dict[str, bytes]] = None,
    private_key_path: Optional[str] = None,
) -> dict:
    """Publish one version of an entity into a catalog tree.

    The package and its manifest are written once into the versioned folder;
    ``latest/entity.json`` is then refreshed. Re-publishing the same version
    with the same content is a no-op, with other content it is refused: a
    published version never changes under a client that pinned it.

    *entity_folder* may be ``None`` for an entity that ships no files (an MCP
    server is a preset): its manifest then carries neither ``files`` nor
    ``package``, which is what the installer expects - a package block the
    catalog cannot serve would be a promise it breaks. *private_key_path*
    signs the manifest and the refreshed pointer.

    Returns a report with ``type``, ``id``, ``version``, ``path``,
    ``package_sha256`` and ``changed``.
    """
    entity_id = _check_id(manifest.get("id"), "id")
    version = _check_version(manifest.get("version"))
    type_ = str(manifest.get("type") or "skill").strip()
    _check_agent_kind(manifest, type_)
    folder_name = type_folder(type_)

    target = version_dir(root, type_, entity_id, version)
    manifest_path = os.path.join(target, "entity.json")
    extra = dict(extra_files or {})
    if entity_folder is None and type_ not in ("mcp", "rag"):
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

    # A prebuilt index is published next to the package rather than inside it:
    # the base installer downloads it through its own URL and verifies that one
    # hash, so the block describing it is derived from the bytes about to be
    # written instead of from what the caller believed they were.
    if type_ == "rag" and "index.db" in extra:
        payload = extra["index.db"]
        distribution = dict(full.get("distribution") or {})
        distribution.setdefault("mode", "prebuilt_index")
        distribution["index_url"] = f"{folder_name}/{entity_id}/{version}/index.db"
        distribution["index_sha256"] = sha256_bytes(payload)
        distribution["index_bytes"] = len(payload)
        full["distribution"] = distribution

    package_path = os.path.join(target, package_name)
    changed = _check_republish(
        target, manifest_path, package_path, extra, full, package, entity_id, version
    )
    if changed:
        os.makedirs(target, exist_ok=True)
        if package:
            with open(package_path, "wb") as handle:
                handle.write(package)
        for name, payload in extra.items():
            with open(os.path.join(target, name), "wb") as handle:
                handle.write(payload)
        _write_json(manifest_path, full)
        _maybe_sign(manifest_path, private_key_path)

    _refresh_latest(root, type_, entity_id, private_key_path=private_key_path)
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


def _refresh_latest(
    root: str,
    type_: str,
    entity_id: str,
    *,
    private_key_path: Optional[str] = None,
) -> Optional[str]:
    """Point ``<type>/<id>/latest/entity.json`` at the newest version.

    The pointer is signed when a key is available: it is the file a client
    fetches to ask for the newest release.
    """
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
    _maybe_sign(latest_path, private_key_path)
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
    # The kind travels with the index entry: the showcase tags an agent card
    # as an employee or a helper without downloading its full manifest.
    if type_ == "agent":
        entry["agent_kind"] = str(entity.get("agent_kind") or "orchestrator")
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


# ─── Signature ─────────────────────────────────────────────────────

def _publish_error(exc) -> "PublishError":
    """Translate a signing failure into a publish refusal."""
    return PublishError(
        str(getattr(exc, "code", "signing_failed")),
        str(getattr(exc, "message", exc)),
        dict(getattr(exc, "details", {}) or {}),
    )


def resolve_signing_key(private_key_path: Optional[str]) -> Optional[str]:
    """Return the signing key path, or None when the environment holds it.

    Publishing has no unsigned mode: without a key the run is refused here
    rather than producing a release nobody can verify.
    """
    source = str(private_key_path or "").strip()
    if source:
        return source
    if os.environ.get(SIGNING_KEY_ENV, "").strip():
        return None
    raise PublishError(
        "signing_key_missing",
        "Publishing requires the Ed25519 private key: pass --sign-key or set "
        + SIGNING_KEY_ENV,
        {},
    )


def sign_manifest(manifest_path: str, private_key_path: Optional[str] = "") -> dict:
    """Sign one manifest and drop ``<manifest>.sig`` beside it.

    An entity manifest is signed at publish time, so an installation can tell
    an entry written by the key holder from one planted in the channel.
    """
    try:
        return write_signature(manifest_path, private_key_path or None)
    except SigningError as exc:
        raise _publish_error(exc) from exc


def sign_index(root: str, private_key_path: Optional[str] = "") -> dict:
    """Sign the bytes of ``index.json`` and write ``index.json.sig``.

    The signature covers the file as stored, so a client verifies the very
    bytes it downloaded. Returns the record that was written.
    """
    index_path = os.path.join(root, "index.json")
    if not os.path.isfile(index_path):
        raise PublishError("index_missing", "index.json is missing or unreadable", {})
    return sign_manifest(index_path, private_key_path)


def verify_index_signature(root: str, public_key_path: str) -> dict:
    """Check ``index.json.sig`` against ``index.json`` and a trusted key.

    *public_key_path* may be one PEM file or a keyring folder; a folder trusts
    every readable key in it, which lets a retiring key and its replacement
    verify at the same time. A missing signature is reported, not raised.
    """
    index_path = os.path.join(root, "index.json")
    if not os.path.isfile(index_path):
        return {"ok": False, "reason": "index_missing"}
    if not os.path.isfile(index_path + ".sig"):
        return {"ok": False, "reason": "signature_missing"}
    path = str(public_key_path or "")
    key_dir = path if os.path.isdir(path) else None
    keys = None
    if key_dir is None:
        try:
            key = load_public_key(path)
        except SigningError:
            return {"ok": False, "reason": "key_unreadable"}
        keys = {key_id_of(key): key}
    result = verify_file(index_path, key_dir=key_dir, keys=keys)
    reason = str(result.get("reason") or "")
    if reason == "signature_invalid":
        reason = "index_changed"
    return {"ok": bool(result.get("ok")), "reason": reason, "key_id": result.get("key_id")}


# ─── One-call publish ──────────────────────────────────────────────────

def publish(
    root: str,
    entity_folder: Optional[str],
    manifest: dict,
    *,
    private_key_path: Optional[str] = None,
    key_id: str = "",
    channel: str = "main",
) -> dict:
    """Publish one entity version, sign every manifest and sign the index.

    The order is the contract: the immutable version is written, its manifest
    is signed, the pointers are refreshed, the index is rebuilt and signed
    last. A run without a key is refused before anything is written: an
    unsigned release looks exactly like a signed one to a client that cannot
    check it. *key_id* is accepted for compatibility and ignored.
    """
    signing_key = resolve_signing_key(private_key_path)
    report = publish_entity(root, entity_folder, manifest, private_key_path=signing_key)
    index = rebuild_index(root, channel=channel)
    index_record = sign_index(root, signing_key)
    keys_dir = os.path.join(root, "keys")
    entity_path = os.path.join(root, str(report.get("path") or ""))
    entity_check = verify_file(entity_path, key_dir=keys_dir) if os.path.isfile(entity_path) else {}
    index_check = verify_index_signature(root, keys_dir)
    report["index_entities"] = len(index.get("entities") or [])
    report["key_id"] = index_record.get("key_id")
    report["signed"] = True
    report["signature_verified"] = bool(entity_check.get("ok"))
    report["index_signature_verified"] = bool(index_check.get("ok"))
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
    parser.add_argument("--key-id", default="",
                        help="accepted for compatibility; the id comes from the key")
    parser.add_argument("--public-key", default="",
                        help="keyring folder or PEM file used by --verify-only")
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
        # The keyring is the trust anchor: every key in it verifies, so a
        # rotation keeps the catalog readable under either key.
        keys_dir = args.public_key or os.path.join(root, "keys")
        check = verify_index_signature(root, keys_dir)
        print(json.dumps(check, ensure_ascii=False, indent=2))
        return 0 if check.get("ok") else 1

    if args.init_key:
        private_path = args.private_key or os.path.expanduser("~/.sagaai/marketplace.pem")
        keys_dir = os.path.join(root, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        staging = os.path.join(keys_dir, ".pending.pub")
        report = generate_keypair(private_path, staging)
        # The public half is named after the key it holds, so the file name and
        # the signature record can never disagree.
        public_path = os.path.join(keys_dir, f"{report['key_id']}.pub")
        os.replace(staging, public_path)
        report["public_path"] = public_path
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
