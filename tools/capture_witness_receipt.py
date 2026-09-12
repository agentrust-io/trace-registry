#!/usr/bin/env python3
"""Capture an external witness receipt for a checkpoint, and record what happened.

Submits a checkpoint file verbatim to a witness, reads the receipt back by log
id and by digest, writes the response bodies, a capture manifest, the offline
verification result and SHA256SUMS into one evidence directory.

Every recorded status, timestamp and hash comes from an observed response. A
request that fails is recorded as it failed. Nothing here reconstructs a field
from a later artifact: the September 7, 2026 capture was assembled by hand and
lost a POST status to a local logging error, which then had to be labelled as
inferred in its manifest. This tool exists so the provenance record is a
transcript rather than a reconstruction.

The manifest and SHA256SUMS are integrity aids for the packet, not signed
witness statements. Only tools/verify_witness_receipt.py establishes the
cryptographic binding, and it runs here over the captured bytes.

Usage:
    python tools/capture_witness_receipt.py \
      --checkpoint docs/evidence/witness-2026-09-07/checkpoint-1.json \
      --out docs/evidence/witness-2026-09-12 \
      --witness-base https://witness.agentactioncapsule.org \
      --expected-log-id trace-registry/v1 \
      --registry-key HEX --witness-key HEX \
      [--did-url https://anchor.agentactioncapsule.org/.well-known/did.json] \
      [--source-commit SHA] [--source-path registry/2026/09/01.ndjson] \
      [--timeout 30]

Exit codes:
    0  Captured, and the receipt verified offline against the pinned keys.
    1  Captured, but verification failed or a request did not return 200. The
       directory still holds whatever was observed, including the failure.
    2  Bad arguments, unreadable checkpoint, or a refused URL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_witness_receipt as vwr

CHECKPOINT_CONTENT_TYPE = 'application/cll-checkpoint+json'
UA = 'trace-registry/capture-witness-receipt (github.com/agentrust-io/trace-registry)'
CHECKPOINT_FILENAME = 'checkpoint-1.json'
POST_FILENAME = 'witness-post.json'
READBACK_FILENAME = 'witness-readback.json'
INCLUSION_FILENAME = 'witness-inclusion.json'
DID_FILENAME = 'witness-did.json'
MANIFEST_FILENAME = 'capture-manifest.json'
VERIFICATION_FILENAME = 'verification.json'
SUMS_FILENAME = 'SHA256SUMS'


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def witness_key_id(key_hex):
    """The witness's own key id: first 16 hex characters of SHA-256(raw public key)."""
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:16]


def check_url_allowed(url, allowed_hosts):
    """Return None if url is safe to fetch, else a rejection reason.

    Mirrors the guard in check_mirrors.py. The base URL is an operator argument
    rather than repo-controlled data, so https and an allowlist derived from
    that base are still enforced before anything is sent.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return 'cannot parse URL: ' + str(exc)
    if parsed.scheme != 'https':
        return 'scheme ' + repr(parsed.scheme) + ' not allowed (https only)'
    host = (parsed.hostname or '').lower()
    if host not in allowed_hosts:
        return 'host ' + repr(host) + ' not in allowlist ' + repr(sorted(allowed_hosts))
    return None


def request(url, allowed_hosts, *, timeout, body=None, content_type=None):
    """Perform one request and return an observation of what came back.

    Never raises for an HTTP error status or a transport failure. The caller
    records the observation either way, because a failed request is part of the
    capture rather than a reason to lose it.
    """
    reason = check_url_allowed(url, allowed_hosts)
    if reason is not None:
        raise ValueError('refusing to fetch ' + url + ': ' + reason)
    headers = {'User-Agent': UA, 'Accept': 'application/json'}
    if content_type is not None:
        headers['Content-Type'] = content_type
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method='POST' if body is not None else 'GET')
    observation = {'method': req.get_method(), 'url': url}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            observation['status'] = response.status
            observation['body'] = response.read()
    except urllib.error.HTTPError as exc:
        observation['status'] = exc.code
        observation['body'] = exc.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        observation['status'] = None
        observation['body'] = None
        observation['error'] = type(exc).__name__ + ': ' + str(exc)
    observation['captured_at'] = now_iso()
    return observation


def receipt_of(body):
    """The receipt_b64 a response carries, or None if it carries none."""
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed.get('receipt_b64') if isinstance(parsed, dict) else None


def write_sums(out):
    """Write SHA256SUMS over every file in the directory except itself.

    LF endings: sha256sum -c cannot open a filename that ends in a carriage
    return, and the September 7 packet shipped its sums file with CRLF.
    """
    lines = []
    for path in sorted(p for p in out.iterdir() if p.is_file() and p.name != SUMS_FILENAME):
        lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name)
    (out / SUMS_FILENAME).write_bytes(('\n'.join(lines) + '\n').encode())


def checkpoint_from_registry_entry(path, batch_id=None):
    """Return (checkpoint_bytes, batch_id) for the entry's mmr_checkpoint.

    A checkpoint is published nested inside a registry entry line, so capturing
    one used to mean extracting it into a file by hand first. That is the step
    where a capture goes wrong quietly: send the whole entry and the witness
    registers a digest over the wrong object, and nothing downstream says so
    because the digest it returns is consistent with what it was given.

    Re-serializing is safe. The witness registers the signing-body digest,
    which is computed from the nine signed fields rather than from these bytes,
    so whitespace here cannot change the entry hash or dodge the witness's
    deduplication. Sorted-key compact JSON is used so the same checkpoint
    always produces the same file.
    """
    entries = []
    for lineno, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit('error: ' + str(path) + ':' + str(lineno) + ': invalid JSON: ' + str(exc))
        if not isinstance(entry, dict):
            raise SystemExit('error: ' + str(path) + ':' + str(lineno) + ': entry is not a JSON object')
        if batch_id is not None and entry.get('batch_id') != batch_id:
            continue
        if isinstance(entry.get('mmr_checkpoint'), dict):
            entries.append(entry)

    if not entries:
        raise SystemExit('error: no entry with an mmr_checkpoint found in ' + str(path)
                         + (' for batch_id ' + repr(batch_id) if batch_id else ''))
    if len(entries) > 1:
        raise SystemExit('error: ' + str(path) + ' carries ' + str(len(entries))
                         + ' checkpointed entries; select one with --batch-id')

    entry = entries[0]
    checkpoint = entry['mmr_checkpoint']
    missing = [field for field in vwr.FIELDS if field not in checkpoint]
    if missing:
        raise SystemExit('error: checkpoint is missing signed field(s): ' + ', '.join(missing))
    encoded = json.dumps(checkpoint, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True).encode('ascii')
    return encoded, entry.get('batch_id')


def capture(*, out, witness_base, expected_log_id, registry_key, witness_key,
            checkpoint_path=None, checkpoint_bytes=None, did_url=None,
            source_commit=None, source_path=None, timeout=30):
    if (checkpoint_path is None) == (checkpoint_bytes is None):
        raise SystemExit('error: pass exactly one of checkpoint_path or checkpoint_bytes')
    if checkpoint_bytes is None:
        checkpoint_bytes = checkpoint_path.read_bytes()
    checkpoint = json.loads(checkpoint_bytes)
    digest = vwr.signing_body_digest(vwr.signing_body(checkpoint)).hex()

    base = witness_base.rstrip('/')
    allowed_hosts = frozenset(
        host for host in ((urllib.parse.urlparse(url).hostname or '').lower()
                          for url in (base, did_url) if url) if host)

    out.mkdir(parents=True, exist_ok=True)
    (out / CHECKPOINT_FILENAME).write_bytes(checkpoint_bytes)

    planned = [
        (POST_FILENAME, base + '/checkpoints', checkpoint_bytes),
        (READBACK_FILENAME, base + '/checkpoints/' + urllib.parse.quote(expected_log_id), None),
        (INCLUSION_FILENAME, base + '/v1/inclusion/' + digest, None),
    ]
    if did_url:
        planned.append((DID_FILENAME, did_url, None))

    events = []
    failures = []
    for filename, url, body in planned:
        observation = request(url, allowed_hosts, timeout=timeout, body=body,
                              content_type=CHECKPOINT_CONTENT_TYPE if body is not None else None)
        event = {'method': observation['method'], 'url': url, 'status': observation['status'],
                 'response_file': filename, 'captured_at': observation['captured_at']}
        if observation['body'] is None:
            event['error'] = observation.get('error', 'no response body')
            failures.append(filename + ': ' + event['error'])
        else:
            (out / filename).write_bytes(observation['body'])
            event['sha256'] = hashlib.sha256(observation['body']).hexdigest()
            if observation['status'] != 200:
                failures.append(filename + ': HTTP ' + str(observation['status']))
        events.append(event)

    carriers = [name for name, _, _ in planned if name != DID_FILENAME]
    receipts = {name: receipt_of((out / name).read_bytes()) for name in carriers
                if (out / name).exists()}
    identical = (len(receipts) == len(carriers)
                 and None not in receipts.values()
                 and len(set(receipts.values())) == 1)

    verification = {'verified': False, 'error': 'no POST response body to verify'}
    if (out / POST_FILENAME).exists():
        try:
            verification = vwr.verify(checkpoint, vwr.load_json(out / POST_FILENAME),
                                      registry_key=registry_key, witness_key=witness_key,
                                      expected_log_id=expected_log_id)
        except Exception as exc:  # a malformed response is a result, not a crash
            verification = {'verified': False, 'error': type(exc).__name__ + ': ' + str(exc)}

    manifest = {
        'source_commit': source_commit,
        'source_path': source_path,
        'request_sha256': hashlib.sha256(checkpoint_bytes).hexdigest(),
        'checkpoint_signing_digest': digest,
        'expected_log_id': expected_log_id,
        'registry_signature_verified': bool(verification.get('checks', {}).get('checkpoint_signature')),
        'witness_key_hex': witness_key,
        'witness_key_id': witness_key_id(witness_key),
        'receipt_bytes_identical_across_responses': identical,
        'events': events,
    }

    (out / VERIFICATION_FILENAME).write_bytes((json.dumps(verification, indent=2) + '\n').encode())
    (out / MANIFEST_FILENAME).write_bytes((json.dumps(manifest, indent=2) + '\n').encode())
    write_sums(out)

    print(json.dumps({'out': str(out), 'verified': verification.get('verified', False),
                      'receipt_bytes_identical_across_responses': identical,
                      'failures': failures}, indent=2))
    if failures:
        print('requests that did not return 200: ' + '; '.join(failures), file=sys.stderr)
    if not identical:
        print('captured responses do not all carry the same receipt bytes', file=sys.stderr)
    return 0 if verification.get('verified') and not failures and identical else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--checkpoint', help='checkpoint JSON file, sent verbatim')
    source.add_argument('--registry-entry',
                        help='registry .ndjson file; the entry\'s mmr_checkpoint is '
                             'extracted and sent, so capturing a published '
                             'checkpoint takes no hand-editing')
    parser.add_argument('--batch-id',
                        help='select one entry from a multi-line registry file')
    parser.add_argument('--out', required=True, help='evidence directory to write')
    parser.add_argument('--witness-base', required=True, help='https base URL of the witness')
    parser.add_argument('--expected-log-id', required=True)
    parser.add_argument('--registry-key', required=True,
                        help='independently accepted raw Ed25519 public key, hex')
    parser.add_argument('--witness-key', required=True,
                        help='independently accepted raw Ed25519 public key, hex')
    parser.add_argument('--did-url', help='witness DID document to record alongside the capture')
    parser.add_argument('--source-commit', help='registry commit the checkpoint came from')
    parser.add_argument('--source-path', help='registry path the checkpoint came from')
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args(argv)

    checkpoint_path = checkpoint_bytes = None
    source_path = args.source_path
    if args.registry_entry:
        checkpoint_bytes, _ = checkpoint_from_registry_entry(
            Path(args.registry_entry), args.batch_id)
        # The entry file is where the checkpoint actually came from, so record
        # it unless the caller named something else. A capture manifest whose
        # provenance field is empty is a manifest a reader cannot re-walk.
        if source_path is None:
            source_path = args.registry_entry
    else:
        checkpoint_path = Path(args.checkpoint)

    try:
        return capture(checkpoint_path=checkpoint_path, checkpoint_bytes=checkpoint_bytes,
                       out=Path(args.out),
                       witness_base=args.witness_base, expected_log_id=args.expected_log_id,
                       registry_key=args.registry_key, witness_key=args.witness_key,
                       did_url=args.did_url, source_commit=args.source_commit,
                       source_path=source_path, timeout=args.timeout)
    except (OSError, ValueError) as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
