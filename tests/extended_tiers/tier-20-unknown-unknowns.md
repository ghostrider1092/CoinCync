# Tier 20 — Unknown Unknowns

_Processes for discovering threats that haven't been imagined yet._

---

## Processes that surface unknowns

### 1. "What worries you?" meetings (quarterly)
Every team member answers:
- What keeps you up at night about the project?
- What feels under-examined?
- What would you bet on breaking in the next year?

### 2. Pre-mortems (before each major launch)
Imagine it's one year later and the launch failed catastrophically. Describe what happened. Compare team answers.

### 3. Documented assumptions
Write down every assumption:
- "Ring signatures prevent linkability"
- "Ristretto group has no exploitable structure"
- "Seed nodes stay online"

Each becomes investigatable.

### 4. Bug bounty program
- Scoped clearly
- Pays $20k-$50k for critical
- 24-hour acknowledgment, 1-week triage
- Budget: $50k-$150k/year post-mainnet

### 5. External audit (multiple angles)
- Code review (general)
- Formal verification (cryptography)
- Penetration testing (infrastructure)
- Operational security (processes)

### 6. Chaos engineering
- Randomly inject faults in sandbox
- Randomized test parameters
- Observe what surprises you

---

## The three questions (ask after building anything significant)

1. **What could cause this to fail in ways I haven't tested?**
2. **What would an adversary with nation-state resources do?**
3. **What are the second-order effects I haven't considered?**

---

## Measuring the pipeline

- How many new threats added to Tier 15 this quarter?
- How many promoted to regression tests?
- Discovered by team vs. external researchers?
- Through processes vs. by accident?

Low numbers = not looking. High numbers = actively managing blind spots.

---

**Last reviewed:** 2026-04-20
**Status:** Never complete. Continuous.
