# Mirroring the TRACE Registry

The TRACE Registry's tamper-evidence guarantee requires that the git commit history be independently held by multiple organizations. A single-point-of-failure undermines the audit trail. This document explains what a mirror does, how to set one up, and how mirrors stay in sync.

## What a mirror does

A mirror is a full clone of this repository held by an independent organization. It must:

1. Stay synchronized with the canonical repo (push or periodic pull).
2. Publish its current HEAD commit SHA at a stable public URL.
3. Raise an alert if its HEAD diverges from the canonical repo (which signals a possible history rewrite).

A mirror does **not** accept anchoring PRs, validate producer keys, or run CI. It is a read-only replica.

## Setting up a GitHub mirror

### Step 1: Fork or clone to your organization

The simplest approach is a GitHub fork under your organization. Go to https://github.com/agentrust-io/trace-registry and click **Fork**. Set the fork to public.

If you prefer an independent clone (recommended for maximum independence from GitHub), use any git hosting that exposes a public-facing HTTP clone URL and an API endpoint that returns the current HEAD SHA.

### Step 2: Keep it synchronized

Add a GitHub Actions workflow to your fork that syncs from the canonical repo daily:

```yaml
# .github/workflows/sync-mirror.yml
name: Sync mirror

on:
  schedule:
    - cron: "0 */6 * * *"  # every 6 hours
  workflow_dispatch:

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Fetch and fast-forward from canonical
        run: |
          git remote add canonical https://github.com/agentrust-io/trace-registry.git || true
          git fetch canonical main
          # Refuse to sync if the canonical has rewound history
          if ! git merge-base --is-ancestor HEAD canonical/main; then
            echo "ERROR: canonical/main is not a descendant of our HEAD -- possible history rewrite"
            exit 1
          fi
          git merge --ff-only canonical/main
          git push origin main
```

The `merge-base --is-ancestor` check is the core safety gate: it detects history rewrites before accepting them.

### Step 3: Publish your HEAD SHA

The `check_mirrors.py` tool reads HEAD SHA from the GitHub API (`https://api.github.com/repos/{owner}/{repo}/commits/HEAD`). If your mirror is a GitHub repo, this works out of the box with no extra configuration.

If you use non-GitHub hosting, expose a URL that returns a JSON object containing `"sha"` at the top level:

```json
{"sha": "abc123...", "url": "https://your-host.example.com/trace-registry.git"}
```

### Step 4: Register as a mirror

Open a pull request against the canonical repo adding your entry to `mirrors.json` and `MIRRORS.md`. See `MIRRORS.md` for the exact format.

Requirements for registration:

- Your organization is independent from Opaque Systems.
- Your mirror is publicly accessible (no authentication required to read).
- You commit to keeping the mirror running for at least 12 months, or to removing the entry if you stop.
- You have a published security contact.

### Step 5: Set up divergence alerts

Add a step to your sync workflow that calls back to `check_mirrors.py` (or replicates its logic) and pages your on-call if your mirror's HEAD diverges from canonical:

```yaml
      - name: Alert on divergence
        if: failure()
        run: |
          curl -X POST "${{ secrets.ALERT_WEBHOOK_URL }}" \
            -H "Content-Type: application/json" \
            -d '{"text": "TRACE Registry mirror sync failed -- possible history rewrite"}'
```

## Non-GitHub mirrors

The `head_api` field in `mirrors.json` accepts any HTTPS URL that responds with a JSON object containing `"sha"`. This allows mirrors on Gitea, Forgejo, self-hosted GitLab, or a static host that publishes a `head.json` file.

For a static host, add a step to your sync workflow that writes and publishes the current HEAD:

```bash
echo "{\"sha\": \"$(git rev-parse HEAD)\"}" > head.json
# push head.json to your static host here
```

## Verifying mirror integrity

Any auditor can independently verify a mirror by:

1. Cloning the mirror.
2. Cloning the canonical repo.
3. Confirming both have the same HEAD commit SHA.
4. Walking the Merkle roots in each registry NDJSON line and confirming the git commit history is the only thing that could have produced them.

The `tools/check_mirrors.py` script automates steps 1-3 using only the public APIs, requiring no local clone.
