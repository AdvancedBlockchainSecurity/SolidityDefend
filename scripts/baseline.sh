#!/usr/bin/env bash
#
# baseline.sh — reliable, reproducible SolidityDefend baseline.
#
# Builds the release binary, runs the tool's OWN ground-truth validation
# (--validate) plus a clean-contract false-positive check and a per-target
# findings census. Uses -o (file output) and --validate exclusively, so it
# never scrapes the banner-wrapped stdout — results are deterministic.
#
# Invariants enforced (non-zero exit if violated), so this is also a CI gate:
#   1. Recall == 100%   (no expected true positive may be missed)
#   2. Clean-contract false positives == 0
#
# Usage:
#   scripts/baseline.sh                 # human-readable report to stdout
#   scripts/baseline.sh --json          # machine-readable summary JSON only
#   BIN=path/to/soliditydefend scripts/baseline.sh   # use a prebuilt binary
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GROUND_TRUTH="tests/validation/ground_truth.json"
JSON_ONLY=0
[ "${1:-}" = "--json" ] && JSON_ONLY=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- build (skip if BIN provided and exists) ---------------------------------
BIN="${BIN:-./target/release/soliditydefend}"
if [ ! -x "$BIN" ]; then
  [ "$JSON_ONLY" -eq 1 ] || echo "Building release binary..." >&2
  cargo build --release --bin soliditydefend >/dev/null 2>&1
  BIN="./target/release/soliditydefend"
fi

VERSION="$("$BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
DETECTORS="$("$BIN" --list-detectors 2>/dev/null | grep -cE '^\s+[a-z0-9][a-z0-9-]+ ' || true)"

# --- clean contracts: every finding here is a false positive -----------------
CLEAN_TARGETS=(
  tests/contracts/clean_examples/clean_contract.sol
  tests/contracts/fp_benchmarks/safe_amm_pool.sol
  tests/contracts/fp_benchmarks/safe_chainlink_consumer.sol
  tests/contracts/fp_benchmarks/safe_erc4626_vault.sol
  tests/contracts/fp_benchmarks/safe_flash_loan_provider.sol
)

# --- vulnerable targets: mix of expected TPs (+ un-annotated extras) ---------
VULN_TARGETS=(
  tests/contracts/basic_vulnerabilities/reentrancy_issues.sol
  tests/contracts/basic_vulnerabilities/validation_issues.sol
  tests/contracts/vulnerable/
  tests/contracts/flash_loans/
  tests/contracts/erc4626_vaults/
  tests/contracts/price-manipulation/
  tests/contracts/cross_chain/
  tests/contracts/delegatecall/
  tests/contracts/signatures/
  tests/contracts/specialized/
  tests/contracts/restaking/
  tests/contracts/account_abstraction/
  tests/contracts/amm_context/
)

# count findings from a CLEAN json file written via -o (no banner)
count_findings () { # $1 = target path
  local out="$WORK/scan.json"
  "$BIN" -f json -o "$out" "$1" >/dev/null 2>&1 || true
  python3 -c "import json,sys
try: print(len(json.load(open('$out')).get('findings',[])))
except Exception: print(0)"
}

# --- ground-truth validation (authoritative recall/precision) ----------------
VAL="$WORK/validate.txt"
"$BIN" --validate --ground-truth "$GROUND_TRUTH" > "$VAL" 2>&1 || true
gt_metric () { grep -E "$1" "$VAL" | head -1 | grep -oE '[0-9]+(\.[0-9]+)?' | tr '\n' ' '; }
TP_LINE="$(grep -E 'True Positives:' "$VAL" | head -1)"
FP_LINE="$(grep -E 'False Positives:' "$VAL" | head -1)"
FN_LINE="$(grep -E 'False Negatives:' "$VAL" | head -1)"
RECALL="$(grep -E '^\s*Recall:' "$VAL" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
PRECISION="$(grep -E '^\s*Precision:' "$VAL" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
F1="$(grep -E 'F1 Score:' "$VAL" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
GT_CONTRACTS="$(grep -oE 'with [0-9]+ contracts' "$VAL" | grep -oE '[0-9]+' | head -1)"

# --- clean FP census ---------------------------------------------------------
CLEAN_FP=0
declare -a CLEAN_ROWS=()
for t in "${CLEAN_TARGETS[@]}"; do
  c=$(count_findings "$t"); CLEAN_FP=$((CLEAN_FP + c))
  CLEAN_ROWS+=("$c|$t")
done

# --- vulnerable findings census ---------------------------------------------
VULN_TOTAL=0
declare -a VULN_ROWS=()
for t in "${VULN_TARGETS[@]}"; do
  c=$(count_findings "$t"); VULN_TOTAL=$((VULN_TOTAL + c))
  VULN_ROWS+=("$c|$t")
done

# --- invariant checks --------------------------------------------------------
STATUS=0
RECALL_OK=1; [ "${RECALL%%.*}" = "100" ] || { RECALL_OK=0; STATUS=1; }
CLEANFP_OK=1; [ "$CLEAN_FP" -eq 0 ] || { CLEANFP_OK=0; STATUS=1; }

if [ "$JSON_ONLY" -eq 1 ]; then
  python3 - "$VERSION" "$DETECTORS" "$RECALL" "$PRECISION" "$F1" "$CLEAN_FP" "$VULN_TOTAL" "$GT_CONTRACTS" "$RECALL_OK" "$CLEANFP_OK" <<'PY'
import json,sys
v,d,rec,prec,f1,cfp,vt,gt,rok,cok = sys.argv[1:]
print(json.dumps({
  "version": v, "detectors": int(d or 0),
  "ground_truth_contracts": int(gt or 0),
  "recall_pct": float(rec or 0), "precision_pct": float(prec or 0), "f1": float(f1 or 0),
  "clean_false_positives": int(cfp), "vulnerable_findings": int(vt),
  "invariants": {"recall_100": bool(int(rok)), "clean_fp_zero": bool(int(cok))}
}, indent=2))
PY
  exit $STATUS
fi

# --- human-readable report ---------------------------------------------------
line() { printf '%s\n' "------------------------------------------------------------"; }
echo "SolidityDefend baseline — v${VERSION}  ($(date +%F))"
line
echo "Active detectors : ${DETECTORS}"
echo "Ground truth     : ${GROUND_TRUTH} (${GT_CONTRACTS} contracts)"
echo
echo "GROUND-TRUTH VALIDATION (authoritative)"
echo "  ${TP_LINE#  }"
echo "  ${FN_LINE#  }"
echo "  ${FP_LINE#  }"
echo "  Precision: ${PRECISION}%   Recall: ${RECALL}%   F1: ${F1}"
echo
echo "CLEAN CONTRACTS (every finding = false positive; target 0)"
for r in "${CLEAN_ROWS[@]}"; do printf "  %-4s %s\n" "${r%%|*}" "${r#*|}"; done
echo "  -> clean false positives: ${CLEAN_FP}"
echo
echo "VULNERABLE TARGETS (findings census)"
for r in "${VULN_ROWS[@]}"; do printf "  %-4s %s\n" "${r%%|*}" "${r#*|}"; done
echo "  -> total vulnerable findings: ${VULN_TOTAL}"
echo
line
echo "INVARIANTS"
printf "  recall == 100%%       : %s\n" "$([ $RECALL_OK -eq 1 ] && echo PASS || echo FAIL)"
printf "  clean FPs == 0       : %s\n" "$([ $CLEANFP_OK -eq 1 ] && echo PASS || echo FAIL)"
line
[ $STATUS -eq 0 ] && echo "BASELINE OK" || echo "BASELINE REGRESSION DETECTED"
exit $STATUS
