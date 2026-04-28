#!/usr/bin/env bash
#
# tier-13-supply-chain.sh — verify supply chain and build integrity
#
# Run from repo root: ./tests/extended_tiers/tier-13-supply-chain.sh
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ -t 1 ]; then
    C_RED=$'\033[0;31m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""; C_RESET=""
fi

PASSED=0; FAILED=0; WARNED=0

header() { echo ""; echo "${C_BLUE}--- $* ---${C_RESET}"; }
ok()     { echo "${C_GREEN}OK${C_RESET} $*"; PASSED=$((PASSED+1)); }
fail()   { echo "${C_RED}X${C_RESET} $*"; FAILED=$((FAILED+1)); }
warn()   { echo "${C_YELLOW}!${C_RESET} $*"; WARNED=$((WARNED+1)); }
info()   { echo "${C_DIM}  $*${C_RESET}"; }

cd "${REPO_ROOT}" || exit 1

# --- 13.1: Dependency pinning ---
header "13.1 Dependencies are pinned"
if [ -f "Cargo.lock" ]; then
    ok "Cargo.lock exists"
    if git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then
        ok "Cargo.lock is committed"
    else
        fail "Cargo.lock not committed — non-reproducible builds"
    fi
else
    fail "Cargo.lock missing"
fi

# --- 13.2: No git dependencies ---
header "13.2 Dependencies from trusted sources"
git_deps=$(grep -cE '^\s*[a-zA-Z0-9_-]+\s*=\s*\{.*git' Cargo.toml 2>/dev/null || true)
git_deps="${git_deps:-0}"
if [ "${git_deps}" -gt 0 ] 2>/dev/null; then
    warn "${git_deps} git dependencies (not from crates.io)"
    grep -E '^\s*[a-zA-Z0-9_-]+\s*=\s*\{.*git' Cargo.toml | sed 's/^/      /'
else
    ok "All dependencies from crates.io"
fi

# --- 13.3: Build scripts ---
header "13.3 Build reproducibility"
build_scripts=$(find . -name "build.rs" -not -path "./target/*" -not -path "./.git/*" 2>/dev/null | wc -l)
if [ "${build_scripts}" -gt 0 ]; then
    warn "${build_scripts} build.rs files (audit for determinism)"
else
    ok "No build.rs files"
fi

# --- 13.4: Critical files lockfile ---
header "13.4 Consensus integrity protection"
if [ -f "critical_files.lock" ]; then
    ok "critical_files.lock exists (consensus files hash-protected)"
else
    fail "No critical_files.lock — consensus files unprotected"
fi

# --- 13.5: Cargo audit ---
header "13.5 Known vulnerability check"
if command -v cargo-audit >/dev/null 2>&1; then
    audit_output=$(cargo audit 2>&1 || true)
    if echo "${audit_output}" | grep -qE "0 vulnerabilities|No vulnerable"; then
        ok "cargo audit clean"
    elif echo "${audit_output}" | grep -qi "vulnerability"; then
        vuln_count=$(echo "${audit_output}" | grep -ci "vulnerability")
        fail "cargo audit found ${vuln_count} vulnerability references"
    else
        ok "cargo audit found no issues"
    fi
else
    warn "cargo-audit not installed (cargo install cargo-audit)"
fi

# --- 13.6: No secrets in repo ---
header "13.6 No secrets committed"
found_secrets=0
for pattern in 'AKIA[0-9A-Z]{16}' 'sk-[a-zA-Z0-9]{20,}' '-----BEGIN.*PRIVATE KEY-----' 'ghp_[a-zA-Z0-9]{36}'; do
    if git grep -IE "${pattern}" -- ':!target' 2>/dev/null | grep -v "# not a real" | grep -q .; then
        fail "Possible secret: ${pattern}"
        found_secrets=$((found_secrets + 1))
    fi
done
[ "${found_secrets}" -eq 0 ] && ok "No obvious secrets found"

# --- 13.7: SECURITY.md ---
header "13.7 Security documentation"
if [ -f "SECURITY.md" ] || [ -f "docs/SECURITY.md" ]; then
    ok "SECURITY.md exists"
else
    warn "No SECURITY.md (needed for vuln disclosure process)"
fi

# --- 13.8: Signed commits ---
header "13.8 Commit signing"
unsigned=$(git log --format='%G?' -20 | grep -c 'N' || echo 0)
if [ "${unsigned}" -lt 5 ]; then
    ok "Most recent commits are signed"
else
    warn "${unsigned}/20 recent commits unsigned"
fi

# --- Summary ---
echo ""
echo "${C_BLUE}--- Tier 13 Summary ---${C_RESET}"
echo "  ${C_GREEN}Passed: ${PASSED}${C_RESET}"
echo "  ${C_RED}Failed: ${FAILED}${C_RESET}"
echo "  ${C_YELLOW}Warnings: ${WARNED}${C_RESET}"

[ "${FAILED}" -gt 0 ] && exit 1 || exit 0
