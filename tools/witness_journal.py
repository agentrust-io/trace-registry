"""Durable, fail-closed submission journal around capture_witness_receipt.

No automatic retry: interrupted/failed attempts remain unknown. Operators must
reconcile retained receipts before deciding whether another submission is safe.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY, checkpoint BLOB NOT NULL, policy TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','inflight','verified','unknown')),
                evidence TEXT, error TEXT)''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, checkpoint: bytes, *, witness_base, expected_log_id, registry_key, witness_key):
        # Exact bytes and explicit trust policy form the idempotency identity.
        # No witness discovery, key rotation, or URL normalization is implicit.
        policy = json.dumps(dict(witness_base=witness_base, expected_log_id=expected_log_id,
                                 registry_key=registry_key, witness_key=witness_key), sort_keys=True)
        identity = hashlib.sha256(checkpoint + b'\x00' + policy.encode()).hexdigest()
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO submissions VALUES (?,?,?,\'pending\',NULL,NULL)',
                       (identity, checkpoint, policy))
        return identity

    def status(self, identity):
        with self.connect() as db:
            row = db.execute('SELECT state,evidence,error FROM submissions WHERE id=?',
                             (identity,)).fetchone()
        if row is None:
            raise KeyError(identity)
        return dict(zip(('state', 'evidence', 'error'), row))

    def submit(self, identity, evidence_root):
        # Claim is committed before network I/O. A crash cannot make work pending
        # again; another worker cannot repeat an inflight/unknown submission.
        import capture_witness_receipt

        directory = Path(evidence_root).resolve() / identity
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT checkpoint,policy,state FROM submissions WHERE id=?',
                             (identity,)).fetchone()
            if row is None:
                raise KeyError(identity)
            if row[2] != 'pending':
                return False
            # Never reuse evidence, including evidence left by another database.
            directory.mkdir(parents=True, exist_ok=False)
            db.execute("UPDATE submissions SET state='inflight',evidence=? WHERE id=?",
                       (str(directory), identity))
        try:
            code = capture_witness_receipt.capture(out=directory, checkpoint_bytes=row[0],
                                                  **json.loads(row[1]))
        except BaseException as exc:
            with self.connect() as db:
                db.execute("UPDATE submissions SET state='unknown',error=? WHERE id=?",
                           (type(exc).__name__ + ': ' + str(exc), identity))
            raise
        with self.connect() as db:
            db.execute('UPDATE submissions SET state=?,error=? WHERE id=?',
                       ('verified' if code == 0 else 'unknown',
                        None if code == 0 else 'capture exit ' + str(code), identity))
        return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    enqueue = commands.add_parser('enqueue')
    enqueue.add_argument('--checkpoint', type=Path, required=True)
    for option in ('witness-base', 'expected-log-id', 'registry-key', 'witness-key'):
        enqueue.add_argument('--' + option, required=True)
    submit = commands.add_parser('submit')
    submit.add_argument('identity')
    submit.add_argument('--evidence-root', type=Path, required=True)
    status = commands.add_parser('status')
    status.add_argument('identity')
    args = parser.parse_args()
    journal = Journal(args.database)
    if args.command == 'enqueue':
        print(journal.enqueue(args.checkpoint.read_bytes(), witness_base=args.witness_base,
              expected_log_id=args.expected_log_id, registry_key=args.registry_key,
              witness_key=args.witness_key))
    elif args.command == 'submit':
        journal.submit(args.identity, args.evidence_root)
        result = journal.status(args.identity)
        print(json.dumps(result, indent=2))
        return 0 if result['state'] == 'verified' else 1
    else:
        print(json.dumps(journal.status(args.identity), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
