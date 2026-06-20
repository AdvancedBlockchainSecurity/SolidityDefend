#!/usr/bin/env bash
# Checks that every top-level detector source file is both declared in lib.rs
# and registered in registry.rs.
#
# Run: ./scripts/check_detector_registration.sh
# Returns exit code 1 if any gaps are found.

set -euo pipefail

DETECTORS_SRC="crates/detectors/src"
LIB="$DETECTORS_SRC/lib.rs"
REGISTRY="$DETECTORS_SRC/registry.rs"

# Framework files that are not detectors
FRAMEWORK_FILES="lib registry utils fp_filter detector types safe_patterns confidence"

# Get all top-level .rs module names (no subdirectory mods)
ALL_FILES=$(
  for f in "$DETECTORS_SRC"/*.rs; do
    basename "$f" .rs
  done \
  | grep -vxF "lib" \
  | grep -vxF "registry" \
  | grep -vxF "utils" \
  | grep -vxF "fp_filter" \
  | grep -vxF "detector" \
  | grep -vxF "types" \
  | grep -vxF "safe_patterns" \
  | grep -vxF "confidence"
)

# Get all pub mod declarations in lib.rs
DECLARED=$(grep "^pub mod" "$LIB" | sed 's/pub mod //;s/;//' | tr -d ' ')

# Get all module names referenced in registry.rs register calls
# Matches: crate::<module>::<StructName> patterns
REGISTERED=$(grep "self\.register" "$REGISTRY" \
  | grep -oE 'crate::[a-z_]+' \
  | sed 's/crate:://' \
  | sort -u)

ERRORS=0

echo "=== Detector Registration Audit ==="
echo ""

for module in $ALL_FILES; do
  declared=false
  registered=false

  if echo "$DECLARED" | grep -qx "$module"; then
    declared=true
  fi

  if echo "$REGISTERED" | grep -qx "$module"; then
    registered=true
  fi

  if [ "$declared" = false ] || [ "$registered" = false ]; then
    status=""
    [ "$declared" = false ] && status="${status}UNDECLARED "
    [ "$registered" = false ] && status="${status}UNREGISTERED"
    echo "  FAIL  $module — $status"
    ERRORS=$((ERRORS + 1))
  fi
done

echo ""
if [ $ERRORS -eq 0 ]; then
  echo "All top-level detector modules are declared and registered. ✓"
  exit 0
else
  echo "$ERRORS module(s) have registration gaps. Add pub mod + self.register() for each."
  exit 1
fi
