# GitHub Rulesets

Importable JSON for the protection rules on the public mirror at
`github.com/Coincync/Coincync-Testnet-`. Apply both before
inviting external contributors or shipping signed releases.

## Files

| File | Target | What it does |
|---|---|---|
| `main-protection-ruleset.json` | `~DEFAULT_BRANCH` (i.e. `main`) | Block deletion + force-push, require linear history, require signed commits, require PR before merge (0-reviewer = solo-merge OK), allow rebase/squash but not merge commits |
| `tag-protection-ruleset.json` | tags matching `refs/tags/v*` | Block creation, deletion, and update of release tags by anyone except repo Admin. Stops a stolen GitHub token from publishing a fake `v1.0.0` |

Both rulesets bypass the Admin role (`actor_id: 5`) so the repo
owner can override in an emergency without disabling the rule.

## Import

```
GitHub → repo Settings → Rules → Rulesets → New ruleset → Import a ruleset
```

Upload each JSON one at a time. Confirm the form auto-fills, click
Create. Repeat for the second file.

## Verify after import

In the **Rulesets** list you should see both:

```
✓ main protection            (Active · Branch · ~DEFAULT_BRANCH · 5 rules)
✓ tag protection (v*)        (Active · Tag    · refs/tags/v*   · 3 rules)
```

Test by trying to delete `main` from the GitHub UI (it should
refuse) and trying to force-push from local (`git push -f origin main`
should be rejected).

## Update flow

Edit the JSON in this directory, commit + push, then in GitHub
re-import (Edit existing ruleset → "Replace from JSON" — or delete
and re-import). Keeping the JSON canonical here means the protection
configuration is version-controlled alongside the code it protects.

## What's NOT here

- **CODEOWNERS-based review requirements.** Solo-dev project; no
  reviewers to require. Add when maintainer count grows.
- **Required status checks.** Wire up when the CI workflow has a
  meaningful pass/fail signal we want to gate merges on.
- **Branch creation restrictions.** Anyone can create branches off
  `main`; only `main` itself is gated.
