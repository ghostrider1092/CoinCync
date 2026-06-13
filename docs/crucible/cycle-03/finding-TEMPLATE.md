# Cycle 03 Finding #NN — [short descriptive title]

**Status:** open / root-caused / fixed.
**Severity:** low / medium / high / critical.
**Builds affected:** `v1.0.11-testnet` (`9b542b56`).
**Discovered:** YYYY-MM-DD by [operator | barns1253 | ...].

## TL;DR

[One-paragraph summary of what's broken or unexpected. A reader
should know whether this affects them after reading this section
alone.]

## Symptom

[The operator-visible signal. Log line, error message, broken UX,
chain divergence, etc. Include the exact text the user sees.]

```text
[paste relevant log lines / output here]
```

## Discovery path

[How it was found. "barns ran X command, observed Y." Concrete steps
a future tester can replicate.]

## Root cause

[The actual technical reason. Should reference specific files +
line numbers where the bug lives. If still under investigation,
list the hypotheses ranked by likelihood.]

## What we know

  - [bullet list of confirmed facts]
  - [...]

## What we don't know

  - [bullet list of open questions]
  - [...]

## Hypotheses (if not yet root-caused)

  1. **[most likely]** [hypothesis with one-sentence rationale]
  2. **[second]** [...]
  3. *(ruled out)* [...]

## Verification methodology when investigating

[Concrete steps a future debugger should take. "Capture pcap on
both ends; check whether…"]

## Impact

  - **Operator UX:** [what does the operator see?]
  - **Privacy:** [does this leak anything?]
  - **Sync:** [does it block progress?]
  - **Other:** [...]

## Fix candidates

  - **Fix A** — [short name]
    - [what it changes]
    - cost / blast radius / pros
  - **Fix B** — [alternative if applicable]

## Verification once fixed

[How we confirm the fix works. Specific Cycle 04 (or later)
reproduction steps that should succeed.]

## Follow-ups

  - [ ] [open task]
  - [ ] [open task]
  - [ ] [open task]
