# TRACE Registry Mirrors

The TRACE Registry is append-only and its tamper-evidence depends on the Merkle history being independently held by multiple organizations. This file lists all known public mirrors.

## Canonical repository

| Field | Value |
|---|---|
| Owner | agentrust-io |
| URL | https://github.com/agentrust-io/trace-registry |
| Contact | security@opaque.co |

## Registered mirrors

No mirrors are registered yet. See [docs/mirroring.md](docs/mirroring.md) for how to become a mirror operator and add your entry here.

If you represent an organization that can hold an independent clone (security research group, university AI governance lab, standards body, or neutral infrastructure provider), please open a pull request adding your entry to both this file and `mirrors.json`.

## Checking mirror health

```bash
python tools/check_mirrors.py
```

This fetches the HEAD commit SHA from each registered mirror via the GitHub API and reports any divergence from the canonical repo. Exit code 0 means all mirrors are in sync.

To check a specific mirror by name:

```bash
python tools/check_mirrors.py --mirror "MyOrg/trace-registry-mirror"
```

## Mirror format (for pull requests)

To register your mirror, add an entry to both this table and `mirrors.json`:

```json
{
  "name": "Your Organization Name",
  "github": "your-org/trace-registry-mirror",
  "clone_url": "https://github.com/your-org/trace-registry-mirror.git",
  "head_api": "https://api.github.com/repos/your-org/trace-registry-mirror/commits/HEAD",
  "contact": "your-security-contact@example.com"
}
```

And add a row to the table above:

| Name | GitHub | Clone URL | Contact | Since |
|---|---|---|---|---|
| Your Organization | your-org/trace-registry-mirror | https://github.com/your-org/trace-registry-mirror | your-security-contact@example.com | YYYY-MM-DD |
