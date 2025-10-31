#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
cd "${REPO_ROOT}"

FORGE_BIN="$(command -v forge || true)"
if [ -z "$FORGE_BIN" ] && [ -x "$HOME/.foundry/bin/forge" ]; then
  FORGE_BIN="$HOME/.foundry/bin/forge"
fi
if [ -z "$FORGE_BIN" ]; then
  echo "forge not found" >&2; exit 1
fi

IN_JSON="test/fixtures/fcl_vectors.json"
OUT_CSV="test/fixtures/fcl_gas_profile.csv"
COUNT=$(jq -r .count "$IN_JSON")
START="${START:-0}"
LIMIT="${LIMIT:-$COUNT}"
END=$(( START + LIMIT ))
if [ $END -gt $COUNT ]; then END=$COUNT; fi

echo "index,gas,msgHash,r,s,x,y" > "$OUT_CSV"
MAX_GAS=0; MAX_IDX=-1; MAX_LINE=

for ((i=START; i<END; i++)); do
  OUT=$(NO_COLOR=1 INDEX=$i "$FORGE_BIN" test --match-test test_profileIndex --via-ir -vvv 2>&1 || true)
  OK=$(echo "$OUT" | awk '/^  OK:/{getline;print $1}')
  GAS=$(echo "$OUT" | awk '/^  GAS:/{getline;print $1}')
  MH=$(echo "$OUT" | awk '/^  MSGHASH:/{getline;print $1}')
  R=$(echo "$OUT" | awk '/^  R:/{getline;print $1}')
  S=$(echo "$OUT" | awk '/^  S:/{getline;print $1}')
  X=$(echo "$OUT" | awk '/^  X:/{getline;print $1}')
  Y=$(echo "$OUT" | awk '/^  Y:/{getline;print $1}')
  if [ "${OK:-0}" = "1" ] && [ -n "${GAS:-}" ]; then
    echo "$i,$GAS,$MH,$R,$S,$X,$Y" >> "$OUT_CSV"
    if [ "$GAS" -gt "$MAX_GAS" ]; then MAX_GAS=$GAS; MAX_IDX=$i; MAX_LINE="$i,$GAS,$MH,$R,$S,$X,$Y"; fi
  fi
  if (( (i-START+1) % 50 == 0 )); then echo "Processed $((i-START+1))/$((END-START))"; fi
done

echo "CSV written: $OUT_CSV"
echo "Max gas: $MAX_GAS at index $MAX_IDX"
echo "Max line: $MAX_LINE"
