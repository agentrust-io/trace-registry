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

Two constraints decide where the sync job can live.

1. **The mirrored branch must carry no commit of yours.** A workflow file committed to the fork's `main` puts the mirror one commit ahead of canonical. From then on its head can never equal canonical's, `merge --ff-only` has nothing to fast-forward to, and the ancestry check below reports a rewrite that did not happen. Keep the job on a separate branch (here `mirror-ops`) and make that branch the repository default, because GitHub runs scheduled workflows from the default branch only.
2. **The default Actions token cannot do the push.** `GITHUB_TOKEN` may not push commits that touch `.github/workflows/`, and canonical `main` changes its workflows regularly. Use a token scoped to the mirror repository alone, with Contents and Workflows write, stored as the secret `MIRROR_PUSH_TOKEN`. A deploy key with write access works too where your organization allows them.

```yaml
# .github/workflows/sync-mirror.yml, on the mirror-ops branch
name: Sync mirror

on:
  schedule:
    - cron: "17,47 * * * *"  # twice an hour
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: sync-mirror
  cancel-in-progress: false

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - name: Fast-forward main from canonical, refuse a rewrite
        env:
          PUSH_TOKEN: ${{ secrets.MIRROR_PUSH_TOKEN }}
        run: |
          set -euo pipefail
          git clone --quiet --branch main "https://github.com/${GITHUB_REPOSITORY}.git" mirror
          cd mirror
          git remote add canonical https://github.com/agentrust-io/trace-registry.git
          git fetch --quiet canonical main
          before="$(git rev-parse HEAD)"
          target="$(git rev-parse canonical/main)"
          # Refuse to sync if canonical no longer descends from what we hold
          if ! git merge-base --is-ancestor "$before" "$target"; then
            echo "::error::canonical main ($target) does not descend from mirror main ($before) -- possible history rewrite"
            exit 1
          fi
          [ "$before" = "$target" ] && exit 0
          git merge --quiet --ff-only canonical/main
          auth="$(printf 'x-access-token:%s' "$PUSH_TOKEN" | base64 | tr -d '\n')"
          git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${auth}" push --quiet origin main
```

The `merge-base --is-ancestor` check is the core safety gate: it detects history rewrites before accepting them. On failure the mirror is left where it was, so the two heads remain as evidence.

Sync more often than the canonical health check runs (every 6 hours). Between a canonical commit and the next sync the mirror is behind, and `check_mirrors.py` reports behind as `diverged`, so a long sync interval shows up as recurring false alarms.

GitHub pauses scheduled workflows in a repository that has seen no activity for 60 days. A mirror of a quiet registry can stop syncing without anything failing. `check_mirrors.py` reports such a mirror as `diverged`, the same status it gives a rewritten one, so a stale mirror is visible but telling the two apart takes an ancestry check between the two heads.

### Step 3: Publish your HEAD SHA

The `check_mirrors.py` tool reads the mirror's head from the URL you register as `head_api`. For a GitHub mirror, register the mirrored branch by name, `https://api.github.com/repos/{owner}/{repo}/commits/main`. `commits/HEAD` resolves to the default branch, which under Step 2 is `mirror-ops` and not the branch being mirrored.

If you use non-GitHub hosting, expose a URL that returns a JSON object containing `"sha"` at the top level:

```json
{"sha": "abc123...", "url": "https://your-host.example.com/trace-registry.git"}
```

### Step 4: Register as a mirror

Open a pull request against the canonical repo adding your entry to `mirrors.json` and `MIRRORS.md`. See `MIRRORS.md` for the exact format.

Requirements for registration:

- Your organization is independent from OPAQUE Systems.
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
