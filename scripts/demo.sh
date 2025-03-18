#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  local sig=$(($? - 128))
  echo "Caught $(kill -l $sig) signal. Killing all background processes and exiting..."
  kill "$(jobs -p)" 2>/dev/null || true
}

trap cleanup INT TERM

BASE_DIR=$(realpath "$(dirname "$(dirname "$0")")")
CONFIG_DIR="${BASE_DIR}/config"
DATA_DIR="${1:-${BASE_DIR}/example_data}"
SCRIPTS_DIR="${BASE_DIR}/scripts"

echo "Preparing data for tests..."

# Process data for each party
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
        "${BASE_DIR}/plink2" --make-bed \
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
    "${BASE_DIR}/plink" --make-bed \
        --bfile "${PARTY_DIR}/chr1" \
        --merge-list "${MERGE_LIST}" \
        --out "${COMBINED}"

    ## Step 3. Convert BED to binary format
    SAMPLE_COUNT=$(wc -l < "${COMBINED}.fam")
    SAMPLE_COUNT=$((SAMPLE_COUNT))
    SNP_COUNT=$(wc -l < "${COMBINED}.bim")
    SNP_COUNT=$((SNP_COUNT))

    echo "Party ${party} has ${SAMPLE_COUNT} samples and ${SNP_COUNT} SNPs."
    echo "Converting ${COMBINED}.bed to binary format..."

    "${SCRIPTS_DIR}/plinkBedToBinary.py" \
            "${COMBINED}.bed" \
            "${SAMPLE_COUNT}" \
            "${SNP_COUNT}" \
            "${COMBINED}.bin"

    ## Prepare additional input files

    # Create chrom_sizes.txt if needed
    if [ ! -f "${PARTY_DIR}/chrom_sizes.txt" ]; then
        echo "Generating chrom_sizes.txt..."
        for chr in {1..22}; do
            SNP_COUNT_CHR=$(grep -c "^${chr}\s" "${COMBINED}.bim" || echo "0")
            echo "${SNP_COUNT_CHR}" >> "${PARTY_DIR}/chrom_sizes.txt"
        done
    fi

    # Create snp_ids.txt if needed
    if [ ! -f "${PARTY_DIR}/snp_ids.txt" ]; then
        echo "Generating snp_ids.txt..."
        awk '{print $2}' "${COMBINED}.bim" > "${PARTY_DIR}/snp_ids.txt"
    fi

    # Create snp_pos.txt if needed
    if [ ! -f "${PARTY_DIR}/snp_pos.txt" ]; then
        echo "Generating snp_pos.txt..."
        awk '{print $1 "\t" $4}' "${COMBINED}.bim" > "${PARTY_DIR}/snp_pos.txt"
    fi

    # Precompute genotype counts
    if [ ! -f "${PARTY_DIR}/all.gcount.transpose.bin" ]; then
        echo "Precomputing genotype counts for party ${party}..."
        PATH="${SCRIPTS_DIR}:$PATH" "precompute_geno_counts.sh" "${PARTY_DIR}/all"
    fi

    ## Step 4. Generate matrix blocks.
    echo "Generating matrix blocks..."
    echo "${SAMPLE_COUNT}" > "${PARTY_DIR}/count.txt"
    echo "${SNP_COUNT}" >> "${PARTY_DIR}/count.txt"
done

BLOCK_SIZE=8192

"${SCRIPTS_DIR}/matrix_text2bin_blocks.py" \
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
