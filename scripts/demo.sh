#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  local sig=$(($? - 128))
  echo "Caught $(kill -l $sig) signal. Killing all background processes and exiting..."
  kill "$(jobs -p)" 2>/dev/null || true
}

trap cleanup INT TERM

### Process data for each party
echo "Preprocessing data for tests..."

BASE_DIR=$(dirname "$(realpath "$(dirname "$0")")")
DATA_DIR="${1:-${BASE_DIR}/example_data}"
PATH="${BASE_DIR}/scripts:${PATH}"

# CP1 and CP2
for pid in 1 2; do
    data_prep.sh "${pid}" "${DATA_DIR}/party${pid}"
done

### Run tests
run_test() {
    echo "Running $1 for party $2"
    PID=$2 sfgwas-lmm -test.run "$1" -test.timeout 96h
}

for t in TestLevel0 TestLevel1 TestAssoc; do
    job_ids=()
    for pid in 0 1 2; do
        run_test $t "$pid" &
        job_ids[pid]=$!
    done
    for job_id in "${job_ids[@]}"; do
        wait "$job_id"
    done
done

trap - INT TERM
