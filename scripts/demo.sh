#!/usr/bin/env bash

set -euo pipefail

run_party() {
    echo "Running party $1"
    PID=$1 go test -run TestLevel0 -timeout 96h
    PID=$1 go test -run TestLevel1 -timeout 96h
    PID=$1 go test -run TestAssoc -timeout 96h
}

run_party 0 &
run_party 1 &
run_party 2 &
wait
