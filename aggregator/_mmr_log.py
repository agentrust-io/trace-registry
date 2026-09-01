"""The aggregator's append-only MMR log and signed checkpoint chain.

Every anchored registry entry (one per batch, unchanged cadence) is folded as
one leaf into a single running MMR spanning the whole registry, and a signed
``CheckpointRecord`` (``trace_verify._checkpoint``) is emitted and attached to
that same entry under ``entry["mmr_checkpoint"]``. Because MMR appends are
O(log n) (``trace_verify._mmr.add_leaf`` never rewrites an existing node) and
checkpoints are a fixed handful of 32-byte hashes regardless of log size,
this adds no per-batch tree rebuild and no growing per-entry cost -- the
scaling problem docs/checkpoint-architecture.md (issue #17) flags for the
per-batch NDJSON write itself is untouched by this module; what this module
adds is cryptographic consistency *between* anchoring runs, which git commit
history alone does not provide (see docs/mmr-checkpoint.md).

Node persistence: ``FileNodeStore`` appends 32-byte node hashes to a flat
binary file and mirrors them in memory. Restart cost is a single sequential
read of that file back into memory (`sync from disk`), not a recomputation
of any hash -- consistent with "streaming appends, no rebuild."
"""
from __future__ import annotations

from pathlib import Path

from trace_verify import _mmr as core
from trace_verify._checkpoint import CheckpointRecord, entry_leaf_digest

NODE_LEN = core.DIGEST_LEN


class FileNodeStore:
    """Append-only, file-backed MMR node store.

    Node hashes are appended to `path` as a flat sequence of 32-byte
    records; the in-memory list is a read cache populated once at
    construction from whatever is already on disk. No node is ever
    rewritten -- `append_nodes` always seeks to end-of-file.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        data = self._path.read_bytes()
        if len(data) % NODE_LEN != 0:
            raise core.IntegrityError(
                f"{path} length {len(data)} is not a multiple of {NODE_LEN} -- "
                "node store file is corrupt or truncated"
            )
        self._nodes: list[bytes] = [data[i : i + NODE_LEN] for i in range(0, len(data), NODE_LEN)]

    def size(self) -> int:
        return len(self._nodes)

    def node(self, pos: int) -> bytes:
        try:
            return self._nodes[pos]
        except IndexError as exc:
            raise IndexError(f"no node at position {pos}") from exc

    def append_nodes(self, hashes: list[bytes]) -> None:
        with self._path.open("ab") as fh:
            for h in hashes:
                fh.write(h)
        self._nodes.extend(hashes)


class Ed25519CheckpointSigner:
    """A persistent Ed25519 signing identity for this aggregator's checkpoints.

    `key_id` is the raw 32-byte public key, hex-encoded (self-contained --
    a verifier needs no separate key registry lookup; see
    `trace_verify._checkpoint.verify_checkpoint_signature_offline`). The
    private key is generated once and persisted PEM-encoded at `key_path`;
    subsequent runs load the same identity rather than rotating silently.
    """

    def __init__(self, key_path: Path | None, *, pem: bytes | None = None) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
            load_pem_private_key,
        )

        if pem is not None:
            # CI path: the identity is supplied out of band (a repository
            # secret) and never touches the working tree. A checkout is
            # ephemeral, so a key persisted to disk here would be a NEW
            # identity on every run -- a fresh key_id and a broken chain
            # every fifteen minutes.
            self._private_key = load_pem_private_key(pem, password=None)
        elif key_path is None:
            raise ValueError(
                "Ed25519CheckpointSigner needs either key_path or pem"
            )
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            if key_path.exists():
                self._private_key = load_pem_private_key(
                    key_path.read_bytes(), password=None
                )
            else:
                self._private_key = Ed25519PrivateKey.generate()
                key_path.write_bytes(
                    self._private_key.private_bytes(
                        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                    )
                )
                try:
                    key_path.chmod(0o600)
                except OSError:
                    pass  # best-effort without POSIX permission bits

        public_bytes = self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.key_id = public_bytes.hex()

    def sign(self, digest_hex: str) -> str:
        signature = self._private_key.sign(digest_hex.encode("ascii"))
        return signature.hex()


class CheckpointLog:
    """Wraps one aggregator-wide MMR + its signed checkpoint chain.

    `log_id` identifies this log (a single aggregator instance runs one log
    today; the field exists so a future multi-log/multi-peer deployment can
    tell checkpoints apart, matching the CLL shape used elsewhere in this
    workspace). State (nodes + latest checkpoint) is persisted under
    `root_dir` so a restarted aggregator resumes the same chain rather than
    starting a new one.
    """

    _LATEST_FILENAME = "latest-checkpoint.json"
    _NODES_FILENAME = "mmr-nodes.bin"
    _KEY_FILENAME = "checkpoint-signing-key.pem"

    def __init__(
        self,
        root_dir: Path | None,
        *,
        log_id: str = "trace-registry/v1",
        signer: "Ed25519CheckpointSigner | None" = None,
        replay_entries: list[dict] | None = None,
    ) -> None:
        import json

        self._root_dir = root_dir
        self._log_id = log_id

        if replay_entries is not None:
            # Stateless mode. The tree is rebuilt from the registry's own
            # published entries rather than read from mmr-nodes.bin, so a
            # scheduled job running in a fresh checkout resumes the real
            # chain instead of starting a new one. See replay_from_entries.
            if signer is None:
                raise ValueError("replay mode requires an explicit signer")
            self._nodes = core.MemoryNodeStore()
            self._signer = signer
            self._latest = replay_from_entries(self._nodes, replay_entries, log_id=log_id)
            return

        if root_dir is None:
            raise ValueError("CheckpointLog needs a root_dir unless replaying")
        self._nodes = FileNodeStore(root_dir / self._NODES_FILENAME)
        self._signer = signer or Ed25519CheckpointSigner(root_dir / self._KEY_FILENAME)

        latest_path = root_dir / self._LATEST_FILENAME
        self._latest: CheckpointRecord | None = None
        if latest_path.exists():
            self._latest = CheckpointRecord.from_dict(json.loads(latest_path.read_text()))
            if self._latest.log_id != log_id:
                raise ValueError(
                    f"{latest_path} belongs to log_id={self._latest.log_id!r}, "
                    f"not {log_id!r} -- refusing to mix two logs' checkpoint chains"
                )

    def append_entry(self, entry: dict, *, timestamp: str) -> CheckpointRecord:
        """Fold `entry` into the MMR as one new leaf and emit + persist the
        next signed checkpoint. Returns the new `CheckpointRecord` (also
        available afterward via `latest`)."""
        leaf_digest = entry_leaf_digest(entry)
        core.add_leaf(self._nodes, core.leaf_hash(leaf_digest))

        new_size = self._nodes.size()
        new_root = core.root_from_peaks(
            [self._nodes.node(p) for p in core.peaks(new_size)]
        ).hex()

        prev = self._latest
        prev_size = prev.mmr_size if prev is not None else 0
        prev_root = prev.root if prev is not None else ""
        consistency_proof = (
            core.consistency_proof(self._nodes, prev_size, new_size) if prev is not None else None
        )

        cp = CheckpointRecord(
            v=1,
            kind="mmr_checkpoint",
            log_id=self._log_id,
            mmr_size=new_size,
            root=new_root,
            prev_size=prev_size,
            prev_root=prev_root,
            key_id=self._signer.key_id,
            timestamp=timestamp,
            signature="",
            consistency_proof=consistency_proof,
        )
        cp.signature = self._signer.sign(cp.digest())

        self._persist_latest(cp)
        self._latest = cp
        return cp

    def _persist_latest(self, cp: CheckpointRecord) -> None:
        import json

        if self._root_dir is None:
            return  # stateless: the entry itself carries the checkpoint
        path = self._root_dir / self._LATEST_FILENAME
        path.write_text(json.dumps(cp.to_dict(), sort_keys=True) + "\n", encoding="utf-8")

    @property
    def latest(self) -> CheckpointRecord | None:
        return self._latest

    def size(self) -> int:
        return self._nodes.size()


def replay_from_entries(
    nodes: "core.NodeAppender",
    entries: list[dict],
    *,
    log_id: str,
) -> CheckpointRecord | None:
    """Rebuild the checkpoint log's MMR from already-published entries.

    Only entries that carry an ``mmr_checkpoint`` are folded, in order. That
    is not a convenience: it is the definition of the tree, and it matches
    exactly what the independent verifier recomputes
    (``tools/verify_checkpoint_chain.py``). Entries anchored before
    checkpointing existed were never leaves of this log and must not become
    leaves retroactively, or every published root would be wrong.

    Fails closed. If the replayed size or root does not reproduce what the
    last published checkpoint claims, the registry's history and its
    checkpoints disagree, and appending a new checkpoint on top would sign
    over that disagreement. Raise instead.
    """
    latest: CheckpointRecord | None = None
    for entry in entries:
        cp_dict = entry.get("mmr_checkpoint")
        if not isinstance(cp_dict, dict):
            continue
        core.add_leaf(nodes, core.leaf_hash(entry_leaf_digest(entry)))
        latest = CheckpointRecord.from_dict(cp_dict)

    if latest is None:
        return None

    if latest.log_id != log_id:
        raise ValueError(
            f"last published checkpoint belongs to log_id={latest.log_id!r}, "
            f"not {log_id!r} -- refusing to mix two logs' checkpoint chains"
        )

    size = nodes.size()
    root = core.root_from_peaks([nodes.node(p) for p in core.peaks(size)]).hex()
    if size != latest.mmr_size or root != latest.root:
        raise core.IntegrityError(
            "replaying the published entries does not reproduce the last "
            f"published checkpoint: replay gives size={size} root={root}, "
            f"checkpoint claims size={latest.mmr_size} root={latest.root}. "
            "The registry and its checkpoint chain disagree; refusing to "
            "extend the chain over an unexplained divergence."
        )
    return latest
