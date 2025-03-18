#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  local sig=$(($? - 128))
  echo "Caught $(kill -l $sig) signal. Killing all background processes and exiting..."
  kill "$(jobs -p)" 2>/dev/null || true
}

trap cleanup INT TERM

### Process data for each party
echo "Preparing data for tests..."

BASE_DIR=$(realpath "$(dirname "$(dirname "$0")")")
DATA_DIR="${1:-${BASE_DIR}/example_data}"
CONFIG_DIR="${BASE_DIR}/config"
PATH="${BASE_DIR}/scripts:${PATH}"

get_config_global() {
    grep "$1" "${CONFIG_DIR}/configGlobal.toml" | cut -d= -f2 | tr -d ' '
}
NUM_PARTIES=$(get_config_global num_main_parties)

for party in $(seq "${NUM_PARTIES}"); do
    echo "Processing data for party ${party}..."
    PARTY_DIR="${DATA_DIR}/party${party}"

    ### Convert genotype data to binary block format

    ## Step 1. Convert PGEN files to PLINK1.9 BED format
    for chr in {1..22}; do
        echo "Converting chromosome ${chr} to BED format..."
        plink2 --make-bed \
               --pfile "${PARTY_DIR}/geno/chr${chr}" \
               --out "${PARTY_DIR}/chr${chr}"
    done

    ## Step 2. Merge BED files
    echo "Merging BED files for party ${party}..."
    MERGE_LIST="${PARTY_DIR}/merge_list.txt"
    for chr in {2..22}; do
        echo "${PARTY_DIR}/chr${chr}" >> "${MERGE_LIST}"
    done
    COMBINED="${PARTY_DIR}/combined"
    plink --make-bed \
          --bfile "${PARTY_DIR}/chr1" \
          --merge-list "${MERGE_LIST}" \
          --out "${COMBINED}"

    ## Step 3. Convert BED to binary format
    SAMPLE_KEEP="${PARTY_DIR}/sample_keep.txt"
    SAMPLE_COUNT=$(wc -l < "${SAMPLE_KEEP}" | cut -d\  -f1)
    SNP_COUNT=$(wc -l < "${PARTY_DIR}/snp_ids.txt" | cut -d\  -f1)

    echo "Party ${party} has ${SAMPLE_COUNT} samples and ${SNP_COUNT} SNPs."
    echo "Converting ${COMBINED}.bed to binary format..."

    plinkBedToBinary.py \
        "${COMBINED}.bed" \
        "${SAMPLE_COUNT}" \
        "${SNP_COUNT}" \
        "${COMBINED}.bin"

    ## Step 4.1. Prepare additional input files
    PGEN_PREFIX="${PARTY_DIR}/geno/chr%d"
    createSnpInfoFiles.py "${PGEN_PREFIX}" "${PARTY_DIR}"
    computeGenoCounts.py "${PGEN_PREFIX}" "${SAMPLE_KEEP}" "${PARTY_DIR}/geno"
    echo "${SAMPLE_COUNT}" > "${PARTY_DIR}/count.txt"
    echo "${SNP_COUNT}" >> "${PARTY_DIR}/count.txt"
done

 ## Step 4.2. Generate matrix blocks.
BLOCK_SIZE=8192
matrix_text2bin_blocks.py \
    "${DATA_DIR}" \
    "${NUM_PARTIES}" \
    "$(get_config_global geno_num_folds)" \
    "${BLOCK_SIZE}" \
    "${DATA_DIR}"

echo "Data preparation complete. Running tests..."

## Step 5. Update local configs.
for party in $(seq 0 "${NUM_PARTIES}"); do
    echo "Updating config for party ${party}..."
    sed -i "s|../example_data|${DATA_DIR}|g" "${CONFIG_DIR}/configLocal.Party${party}.toml"
done

### Run tests
run_test() {
    echo "Running $1 for party $2"
    PID=$2 go test -run "$1" -timeout 96h
}

for t in TestLevel0 TestLevel1 TestAssoc; do
    for pid in $(seq 0 "${NUM_PARTIES}"); do
        run_test $t "$pid" &
    done
    wait
done

trap - INT TERM
