#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  local sig=$(($? - 128))
  echo "Caught $(kill -l $sig) signal. Killing all background processes and exiting..."
  kill "$(jobs -p)" 2>/dev/null || true
}

trap cleanup INT TERM

run_test() {
    echo "Running $1 for party $2"
    PID=$2 go test -run "$1" -timeout 96h
}

for t in TestLevel0 TestLevel1 TestAssoc; do
    for pid in 0 1 2; do
        run_test $t $pid &
    done
    wait
done

trap - INT TERM
