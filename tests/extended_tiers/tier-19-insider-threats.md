# Tier 19 — Insider Threats

_Security policies and access controls protecting against harm from within._

---

## Controls

### 1. Least-privilege access
No single person has access to everything. Audit: domain, DNS, hosting, GitHub admin, signing keys, releases, social media, treasury.

### 2. Separation of duties
Actions requiring 2+ people:
- Publishing release binaries (multi-sig PGP)
- Deploying to mainnet nodes
- Spending from treasury (2-of-3 multisig)
- Access grants
- Incident response decisions

### 3. Audit logging
- Signed git commits required
- Every release logged (who, when, what commit)
- Append-only audit logs
- Quarterly log review

### 4. Separation of dev and production
- No direct SSH to production except emergency break-glass
- Deployments scripted and reproducible
- Emergency manual intervention documented

### 5. Onboarding/Offboarding checklists
- Onboarding: identity verified, access provisioned per role, YubiKey issued
- Offboarding: all access revoked, credentials rotated, signing keys removed

### 6. Duress protocols
- Two-person rules for critical actions
- Warrant canary published regularly
- Legal counsel on retainer

### 7. Monitoring
- Unusual access patterns flagged
- Commit patterns monitored
- Open culture: "is everything okay?" is normal

### 8. Regular reviews
- Quarterly: access audit, multi-sig signer check, key review
- Annual: full audit, threat model update, team training
- Pre-launch: all controls tested end-to-end

---

**Last reviewed:** 2026-04-20
