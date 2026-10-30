#!/usr/bin/env bash
# Enforce the specification's "~15 MB single binary" budget.
#
# The stated target is 15 MB; the gate allows a 1 MB tolerance (16 MiB) so the
# check is about catching accidental dependency bloat, not about failing on
# toolchain/architecture rounding. Actual sizes are always printed.
set -euo pipefail
LIMIT_BYTES=$((16 * 1024 * 1024))
DIST=${1:-dist}
status=0
shopt -s nullglob
printf '%-34s %10s %10s %s\n' ARTEFACT BYTES MiB STATUS
for f in "$DIST"/ghsec-*; do
  [[ -f "$f" ]] || continue
  size=$(wc -c <"$f" | tr -d ' ')
  mib=$(awk -v s="$size" 'BEGIN{printf "%.2f", s/1048576}')
  if (( size > LIMIT_BYTES )); then
    printf '%-34s %10d %10s %s\n' "$(basename "$f")" "$size" "$mib" "FAIL (>16MiB)"
    status=1
  else
    printf '%-34s %10d %10s %s\n' "$(basename "$f")" "$size" "$mib" "ok"
  fi
done
if (( status == 0 )); then
  echo "all artefacts are within the ~15 MB budget (16 MiB hard cap)"
fi
exit $status
