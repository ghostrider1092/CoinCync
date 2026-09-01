# GitHub rulesets — apply before making the repo public

These JSON files are the source of truth for the repository's branch/tag
protection. They are versioned here so the protection policy is reviewable and
recoverable, and so the same rules can be re-applied after any repo migration.

| File | Protects | Effect |
|---|---|---|
| `protect-main.json` | `main` | No direct pushes, force-pushes, or deletion. Every change lands via PR with **1 approving review**, **code-owner review** on the paths in `.github/CODEOWNERS`, **resolved review threads**, and the CI gates (`all-shards`, `hardening-baseline`, `fuzz-gate`) **green and up to date**. |
| `protect-release-tags.json` | `v*` tags | Release tags can't be deleted, moved, or force-updated — a published release can't be swapped out from under verifiers. |

**Owner is not locked out:** the `RepositoryRole` id 5 (Admin) bypass on
`protect-main` (mode `pull_request`) lets the owner merge their own PRs without
a second reviewer (GitHub forbids self-approval), while external contributors
still get the full review + CI gate. Direct pushes / force-pushes / deletions
are blocked for everyone.

## ⚠️ Platform constraint: rulesets need public-or-Pro

On a **private repo on the Free plan**, the rulesets API/UI is gated — creating
one returns `403 "Upgrade to GitHub Pro or make this repository public to enable
this feature."` So there are two safe sequences:

- **No unprotected window (recommended):** enable **GitHub Pro** (or Team) →
  apply the rulesets *while still private* → then flip the repo public. Main is
  protected from the instant it's visible.
- **Free plan:** flip the repo public → **immediately** run the two `gh api`
  commands below (or UI-import). There's a short window between "public" and
  "ruleset applied" where `main` is unprotected — do the apply as the very next
  action, before announcing the repo anywhere.

Branch protection is not available on Free-plan **private** repos either, so a
ruleset is the right mechanism; it just can't be armed until public/Pro.

## Apply

**Option A — UI import (simplest):**
Settings → Rules → Rulesets → New ruleset → **Import a ruleset** → select the
JSON file → review → Create.

**Option B — API (repeatable):**
```bash
gh api -X POST repos/ghostrider1092/CoinCync/rulesets \
  --input .github/rulesets/protect-main.json
gh api -X POST repos/ghostrider1092/CoinCync/rulesets \
  --input .github/rulesets/protect-release-tags.json
```

## After applying — verify before going public

1. Confirm the three status-check contexts (`all-shards`, `hardening-baseline`,
   `fuzz-gate`) match the check names that appear on a real PR. If a workflow's
   job name changes, update both the workflow and `protect-main.json`.
2. Open a throwaway PR and confirm you cannot merge it until the checks pass and
   the code-owner review is in place.
3. Only then flip the repository to public.

## Notes / optional tightenings

- **Signed commits:** add `{ "type": "required_signatures" }` to
  `protect-main.json` once every regular committer signs — it will block
  unsigned commits from non-bypass actors, so don't enable it before contributors
  are set up for signing.
- **Two consensus reviewers:** when a second maintainer exists, raise
  `required_approving_review_count` to 2 for consensus paths (a second, path-
  scoped ruleset over `src/consensus/**`), per CONTRIBUTING.md.
- These rules are `"enforcement": "active"`. To trial them without blocking,
  set `"enforcement": "evaluate"` first and watch the ruleset insights.
