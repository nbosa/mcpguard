"""The audit chain key: loading it, fingerprinting it, rotating it.

The only module that touches key material: the key is never written to the audit
log, never printed and never put into an exception message, only the *key id* is
public, and a key file or key ring that anybody but the owner can read is
refused.  Precedence is ``key``, ``key_file``, ``MCP_GUARD_AUDIT_KEY``,
``MCP_GUARD_AUDIT_KEY_FILE``, the key ring: an explicit argument always beats
the environment.  ``docs/DESIGN.md`` section 2 has the rest.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

#: The key material, the file holding it, the key ring, and the interval.
KEY_ENV = "MCP_GUARD_AUDIT_KEY"
KEY_FILE_ENV = "MCP_GUARD_AUDIT_KEY_FILE"
KEYRING_ENV = "MCP_GUARD_AUDIT_KEYRING"
CHECKPOINT_INTERVAL_ENV = "MCP_GUARD_AUDIT_CHECKPOINT_INTERVAL"

#: The length of a generated key, and the shortest key mcp-guard accepts.
KEY_BYTES = 32
MIN_KEY_BYTES = 16

#: Domain separator of the key id fingerprint: it keeps the key id from being the
#: hash of the bare key, a much more tempting pre-image target with the log in
#: hand.
KEY_ID_DOMAIN = b"mcp-guard/audit-key-id/v1"

#: The permissions a key file or a key ring must have, and any bit for group or
#: other.
PRIVATE_MODE = 0o600
UNSAFE_MODE_BITS = 0o077

#: Placeholder printed instead of the key material anywhere a key is shown.
REDACTED = "<redacted>"

#: How often a keyed log commits to its own running MAC.
DEFAULT_CHECKPOINT_INTERVAL = 100

class AuditKeyError(Exception):
    """The audit key is missing or unusable; never carries key material."""

@dataclass(frozen=True)
class AuditKey:
    """An audit chain key; ``material`` is excluded from ``repr``."""

    key_id: str
    material: bytes = field(repr=False)

    def __repr__(self) -> str:  # pragma: no cover - exercised through the tests
        return f"AuditKey(key_id={self.key_id!r}, material={REDACTED})"

    @classmethod
    def from_material(cls, material: bytes | str) -> "AuditKey":
        """Build a key from raw bytes or from its textual form."""
        normalised = normalise_key(material)
        return cls(key_id=key_id_for(normalised), material=normalised)

    def __len__(self) -> int:
        return len(self.material)

def key_id_for(material: bytes) -> str:
    """The public one way fingerprint that names the key in every record."""
    return hashlib.sha256(KEY_ID_DOMAIN + material).hexdigest()[:16]

def normalise_key(material: bytes | str) -> bytes:
    """Normalise material given as bytes or text (hex is decoded, rest is UTF-8).

    Binary material is used exactly as it is: stripping whitespace from it would
    silently shorten a random key that happens to start or end with one, so the
    key on disk would not be the key that was generated.

    G-18: a text material may carry an explicit encoding tag -- ``hex:`` for
    hexadecimal, ``raw:`` for the UTF-8 bytes themselves.  The tag says how
    the text is to be read, so a key whose bytes happen to look like hex is
    not silently re-interpreted.  An untagged text keeps the old behaviour:
    hex when it can only be hex, UTF-8 otherwise.
    """
    if isinstance(material, (bytes, bytearray)):
        raw = bytes(material)
    else:
        text = str(material).strip()
        tag, separator, body = text.partition(":")
        if separator and tag.lower() in ("hex", "raw"):
            body = body.strip()
            if tag.lower() == "hex":
                if not body or len(body) % 2 or not _is_hex(body):
                    raise AuditKeyError(
                        "the audit key is tagged 'hex:' but its body is not an even number of "
                        "hexadecimal digits"
                    )
                raw = bytes.fromhex(body)
            else:
                raw = body.encode("utf-8")
        elif len(text) >= 32 and len(text) % 2 == 0 and _is_hex(text):
            raw = bytes.fromhex(text)
        else:
            raw = text.encode("utf-8")

    if not raw:
        raise AuditKeyError("the audit key is empty")
    if len(raw) < MIN_KEY_BYTES:
        raise AuditKeyError(
            f"the audit key is too short: {len(raw)} bytes, at least {MIN_KEY_BYTES} are required"
        )
    return raw

def _is_hex(text: str) -> bool:
    return all(character in "0123456789abcdefABCDEF" for character in text)

def generate_key() -> AuditKey:
    """Generate a fresh random audit key."""
    return AuditKey.from_material(secrets.token_bytes(KEY_BYTES))

def check_private_permissions(path: Path, what: str = "key file") -> None:
    """Refuse a key file anybody but the owner can read."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:  # pragma: no cover - the caller has usually opened it already
        raise AuditKeyError(f"the {what} {path} could not be inspected: {exc.strerror}") from None
    if mode & UNSAFE_MODE_BITS:
        raise AuditKeyError(
            f"refusing to use the {what} {path}: its permissions are {mode & 0o777:04o}, "
            f"so it is readable by group or other; fix it with 'chmod 600 {path}'"
        )

def read_key_file(path: str | Path) -> bytes:
    """Read key material from a file, refusing a file that is not private."""
    key_path = Path(path)
    if not key_path.exists():
        raise AuditKeyError(f"the audit key file not found: {key_path}")
    if not key_path.is_file():
        raise AuditKeyError(f"the audit key file is not a regular file: {key_path}")
    check_private_permissions(key_path)
    try:
        text = key_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise AuditKeyError(
            f"the audit key file {key_path} is not valid UTF-8 text; store it as hex (mcp-guard keygen) "
            "or as a passphrase"
        ) from None
    except OSError as exc:
        raise AuditKeyError(f"the audit key file {key_path} could not be read: {exc.strerror}") from None
    return normalise_key(text)

def write_private_file(
    path: str | Path, payload: bytes, *, exclusive: bool = False, refuse: str | None = None
) -> Path:
    """Write ``payload`` to a ``0600`` file, refusing to overwrite by default.

    The one place in mcp-guard that creates a file holding a secret -- the key
    file, the key ring and the keyed sentinel all go through here, so the mode
    and the exclusive create are decided once.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    try:
        descriptor = os.open(target, flags, PRIVATE_MODE)
    except FileExistsError:
        raise AuditKeyError(refuse or f"refusing to overwrite the existing file {target}") from None
    except OSError as exc:
        raise AuditKeyError(f"the file {target} could not be created: {exc.strerror}") from None
    try:
        total = 0
        while total < len(payload):
            written = os.write(descriptor, payload[total:])
            if written == 0:
                raise AuditKeyError(f"short write while writing {target}")
            total += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(target, PRIVATE_MODE)
    return target

def write_key_file(path: str | Path, material: bytes | str, *, force: bool = False) -> Path:
    """Write key material to a new ``0600`` file; ``O_EXCL`` unless ``force``.

    G-18: the file carries an explicit ``hex:`` tag, so the encoding is
    stated rather than inferred.  A key file written by an earlier release
    is still read correctly -- an untagged hex body keeps working.
    """
    return write_private_file(
        path,
        b"hex:" + normalise_key(material).hex().encode("ascii") + b"\n",
        exclusive=not force,
        refuse=f"refusing to overwrite the existing audit key file {path}; pass --force to replace it",
    )

@dataclass
class KeyRing:
    """Every key that has ever signed an audit chain, by key id."""

    keys: dict[str, bytes] = field(default_factory=dict)
    path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "KeyRing":
        ring_path = Path(path)
        if not ring_path.exists():
            raise AuditKeyError(f"the key ring not found: {ring_path}")
        check_private_permissions(ring_path, what="key ring")
        try:
            document: Any = json.loads(ring_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AuditKeyError(f"the key ring {ring_path} is not valid JSON: {exc}") from None
        except OSError as exc:
            raise AuditKeyError(f"the key ring {ring_path} could not be read: {exc.strerror}") from None

        if not isinstance(document, Mapping):  # pragma: no cover - defensive
            raise AuditKeyError(f"the key ring {ring_path} must be a JSON object")

        ring = cls(path=ring_path)
        entries: Mapping[str, Any] = document.get("keys", document)
        for key_id, value in entries.items():
            if not isinstance(key_id, str) or not isinstance(value, str):
                raise AuditKeyError(f"the key ring {ring_path} must map a key id to hex key material")
            material = normalise_key(value)
            actual = key_id_for(material)
            if actual != key_id:
                raise AuditKeyError(
                    f"the key ring {ring_path} lists key id {key_id!r}, but the material it holds is "
                    f"key {actual}"
                )
            ring.keys[key_id] = material
        if not ring.keys:
            raise AuditKeyError(f"the key ring {ring_path} is empty")
        return ring

    def save(self, path: str | Path | None = None) -> Path:
        """Write the key ring back, with mode 0600."""
        target = Path(path) if path is not None else self.path
        if target is None:
            raise AuditKeyError("no key ring path to write to")
        document = {
            "version": 1,
            "keys": {key_id: material.hex() for key_id, material in sorted(self.keys.items())},
        }
        write_private_file(target, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        self.path = target
        return target

    def add(self, key: AuditKey) -> "KeyRing":
        """Add a key, refusing one whose id does not match its material."""
        self.keys[key.key_id] = key.material
        return self

    def get(self, key_id: str) -> AuditKey | None:
        """The key with that id, or ``None``."""
        material = self.keys.get(key_id)
        return AuditKey(key_id=key_id, material=material) if material is not None else None

    def ids(self) -> list[str]:
        """Every key id in the ring, sorted."""
        return sorted(self.keys)

    def __contains__(self, key_id: object) -> bool:
        return key_id in self.keys

    def __len__(self) -> int:
        return len(self.keys)

class KeyResolver:
    """Answers "which key signed this record?" from the key or the key ring."""

    def __init__(self, key: AuditKey | None = None, keyring: KeyRing | None = None) -> None:
        self.primary = key
        self.keyring = keyring

    @classmethod
    def load(
        cls,
        *,
        material: bytes | str | None = None,
        key_file: str | Path | None = None,
        keyring: str | Path | KeyRing | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> "KeyResolver":
        """Build a resolver from the arguments and the environment."""
        environment = os.environ if environ is None else environ
        key = _load_one_key(material=material, key_file=key_file, environ=environment)
        ring: KeyRing | None
        if isinstance(keyring, KeyRing):
            ring = keyring
        elif keyring:
            ring = KeyRing.load(keyring)
        else:
            ring_path = environment.get(KEYRING_ENV)
            ring = KeyRing.load(ring_path) if ring_path else None
        return cls(key=key, keyring=ring)

    @property
    def key_id(self) -> str | None:
        """The id of the key that is currently active."""
        return self.primary.key_id if self.primary is not None else None

    @property
    def has_any_key(self) -> bool:
        return self.primary is not None or (self.keyring is not None and len(self.keyring) > 0)

    def key_for(self, key_id: str) -> AuditKey | None:
        """The key with this id, from the explicit key or from the key ring."""
        if self.primary is not None and self.primary.key_id == key_id:
            return self.primary
        if self.keyring is not None:
            return self.keyring.get(key_id)
        return None

    def ids(self) -> Iterable[str]:
        ids: list[str] = []
        if self.primary is not None:
            ids.append(self.primary.key_id)
        if self.keyring is not None:
            ids.extend(key_id for key_id in self.keyring.ids() if key_id not in ids)
        return ids

def _load_one_key(
    *,
    material: bytes | str | None,
    key_file: str | Path | None,
    environ: Mapping[str, str],
) -> AuditKey | None:
    """Resolve exactly one key, or ``None`` when nothing is configured.

    An explicit argument always beats the environment: the operator who names a
    key file meant that file, and an inherited ``MCP_GUARD_AUDIT_KEY`` must not
    sign a log with a key nobody chose for it.
    """
    if material:
        return AuditKey.from_material(material)
    if key_file:
        return AuditKey.from_material(read_key_file(key_file))
    from_environment = environ.get(KEY_ENV)
    if from_environment:
        return AuditKey.from_material(from_environment)
    path_from_environment = environ.get(KEY_FILE_ENV)
    if path_from_environment:
        return AuditKey.from_material(read_key_file(path_from_environment))
    return None

def resolve_checkpoint_interval(value: int | str | None = None) -> int:
    """The interval: the argument, else the environment, else 100.

    A bad value is a configuration mistake, so it raises ``ValueError`` and the
    command line reports it as a usage error.
    """
    if value is None:
        value = os.environ.get(CHECKPOINT_INTERVAL_ENV)
    if value is None or value == "":
        return DEFAULT_CHECKPOINT_INTERVAL
    try:
        interval = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"the checkpoint interval must be a positive integer, not {value!r}") from None
    if interval < 1:
        raise ValueError(f"the checkpoint interval must be at least 1, not {interval}")
    return interval
