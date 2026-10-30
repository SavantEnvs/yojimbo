#!/usr/bin/env bash
#
# mayhem/build.sh — build yojimbo's five in-tree libFuzzer harnesses (fuzz/) with ASan+UBSan
# (halting) + DWARF 3, a run-once -standalone reproducer for each, and the project's own test
# suite (build-tests/bin/test) with NORMAL flags for mayhem/test.sh. Needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/build-fuzz"            # covered by upstream's /build-*/ .gitignore rule
mkdir -p "$B"

CDEFS="-DNETCODE_DEBUG -DRELIABLE_DEBUG"
CXXDEFS="-DYOJIMBO_DEBUG -DNETCODE_DEBUG -DRELIABLE_DEBUG -DSERIALIZE_DEBUG"
CINC="-Inetcode -Isodium -Ireliable -Ifuzz"
CXXINC="-I. -Iinclude -Isodium -Itlsf -Inetcode -Ireliable -Iserialize -Ifuzz"

# C harness driver for the -standalone reproducers: compile as C so the C++ harnesses' extern "C"
# LLVMFuzzerTestOneInput reference links.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# Two flavors: "fuzz" (SanCov on the whole library, unconditionally — also with empty
# SANITIZER_FLAGS — so the fuzzed code records edges; linked with libFuzzer) and "sa"
# (no SanCov; linked with the run-once driver).
for flavor in fuzz sa; do
  F="$SANITIZER_FLAGS $DEBUG_FLAGS -ffp-contract=off"
  if [ "$flavor" = fuzz ]; then
    F="$F -fsanitize=fuzzer-no-link"; ENGINE="$LIB_FUZZING_ENGINE"; SUF=""
  else
    ENGINE="$B/standalone_main.o"; SUF="-standalone"
  fi
  D="$B/$flavor"; mkdir -p "$D"

  # netcode encrypts zero-length AEAD plaintexts, so libsodium does memcpy(dst, NULL, 0): benign UB
  # in vendored code, exempted for this one TU only (fuzz/README.md).
  $CC $F -fno-sanitize=nonnull-attribute -w -Isodium -c sodium/sodium.c -o "$D/sodium.o"
  $CC $F -w -c tlsf/tlsf.c -o "$D/tlsf.o"
  $CC $F $CDEFS $CINC -c reliable/reliable.c -o "$D/reliable.o"
  $CC $F $CDEFS $CINC -c netcode/netcode.c -o "$D/netcode.o"
  # leak sanitization off at build time (ASan/UBSan stay on)
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$D/lsan_off.o"
  YJ=()
  for s in source/*.cpp; do
    o="$D/yj_$(basename "$s" .cpp).o"
    $CXX -std=c++11 $F $CXXDEFS $CXXINC -c "$s" -o "$o"
    YJ+=("$o")
  done

  $CC $F $ENGINE $CDEFS $CINC fuzz/fuzz_reliable.c "$D/reliable.o" "$D/lsan_off.o" \
      -o "$OUT/fuzz_reliable$SUF"
  $CC $F $ENGINE $CDEFS $CINC fuzz/fuzz_netcode.c "$D/sodium.o" "$D/lsan_off.o" \
      -o "$OUT/fuzz_netcode$SUF"
  $CC $F $ENGINE $CDEFS $CINC fuzz/fuzz_netcode_connect_token.c "$D/sodium.o" "$D/lsan_off.o" \
      -o "$OUT/fuzz_netcode_connect_token$SUF"
  for t in fuzz_connection fuzz_connection_structured; do
    $CXX -std=c++11 $F $ENGINE $CXXDEFS $CXXINC fuzz/$t.cpp "${YJ[@]}" \
        "$D/netcode.o" "$D/reliable.o" "$D/tlsf.o" "$D/sodium.o" "$D/lsan_off.o" \
        -o "$OUT/$t$SUF"
  done
done

# Test suite: upstream's own CMake build, NORMAL flags (no sanitizers, no -gdwarf-3).
env -u CFLAGS -u CXXFLAGS -u LDFLAGS cmake -S . -B build-tests \
    -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" >/dev/null
env -u CFLAGS -u CXXFLAGS -u LDFLAGS cmake --build build-tests -j"$MAYHEM_JOBS" \
    --target yojimbo_test yojimbo_custom_packet_io_test
