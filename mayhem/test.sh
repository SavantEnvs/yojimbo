#!/usr/bin/env bash
#
# mayhem/test.sh — RUN yojimbo's own test suite (built by mayhem/build.sh into build-tests/bin).
# The runner asserts values itself (serialize/netcode/reliable/yojimbo known-answer + round-trip
# checks, golden wire format, AEAD vectors) and prints each test it completes; we parse that output,
# so a neutered/no-op binary (empty stdout) fails instead of "passing" on its exit code.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped" "$pending" "$other" 2>/dev/null || true
  [ "$failed" -eq 0 ]
}

BIN=build-tests/bin
for b in test custom_packet_io_test; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — mayhem/build.sh should have built it" >&2; emit_ctrf yojimbo-test 0 1; exit 1; }
done

out=$(mktemp); trap 'rm -f "$out"' EXIT
"$BIN/test" 12345 > "$out" 2>&1; rc=$?
tail -n 5 "$out"

# every completed test prints its own name (test_*); the runner exits non-zero on the first failed check
names=$(grep -cE '^test_[a-z0-9_]+$' "$out" || true)
passed=0; failed=0
if [ "$rc" -eq 0 ] && grep -q '^\*\*\* ALL TESTS PASS \*\*\*$' "$out" && [ "$names" -ge 100 ]; then
  passed=$names
else
  echo "yojimbo test runner failed (rc=$rc, $names tests printed)" >&2
  passed=$(( names > 0 ? names - 1 : 0 )); failed=1
fi

# second suite: custom packet I/O handshake; asserts via its own checks and prints a fixed OK line
cout=$("$BIN/custom_packet_io_test" 2>&1); crc=$?
echo "$cout" | tail -n 2
if [ "$crc" -eq 0 ] && grep -q '^OK: custom packet I/O handshake' <<<"$cout"; then
  passed=$(( passed + 1 ))
else
  failed=$(( failed + 1 ))
fi

emit_ctrf yojimbo-test "$passed" "$failed"
