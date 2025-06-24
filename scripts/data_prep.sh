#!/usr/bin/env bash

set -euo pipefail

PID="$1" # Party ID (1, 2)
BASE_DIR=$(dirname "$(realpath "$(dirname "$0")")")
EXAMPLE_DATA_DIR="example_data/party${PID}"
DATA_DIR="${2:-"${BASE_DIR}/${EXAMPLE_DATA_DIR}"}"
CONFIG_DIR="${BASE_DIR}/config"
PATH="${BASE_DIR}/scripts:${PATH}"

echo "Preparing data for party ${PID}..."

## Step 1. Convert PGEN files to PLINK1.9 BED format
for chr in {1..22}; do
    echo "Converting chromosome ${chr} to BED format..."
    plink2 --make-bed \
            --pfile "${DATA_DIR}/geno/chr${chr}" \
            --out "${DATA_DIR}/chr${chr}"
done

## Step 2. Merge BED files
echo "Merging BED files..."
MERGE_LIST="${DATA_DIR}/merge_list.txt"
for chr in {2..22}; do
    echo "${DATA_DIR}/chr${chr}" >> "${MERGE_LIST}"
done
COMBINED="${DATA_DIR}/combined"
plink --make-bed \
        --bfile "${DATA_DIR}/chr1" \
        --merge-list "${MERGE_LIST}" \
        --out "${COMBINED}"

## Step 3. Convert BED to binary format
SAMPLE_KEEP="${DATA_DIR}/sample_keep.txt"
SAMPLE_COUNT=$(wc -l < "${SAMPLE_KEEP}" | cut -d\  -f1)
SNP_COUNT=$(wc -l < "${DATA_DIR}/snp_ids.txt" | cut -d\  -f1)

echo "${SAMPLE_COUNT} samples and ${SNP_COUNT} SNPs."
echo "Converting ${COMBINED}.bed to binary format..."

plinkBedToBinary.py \
    "${COMBINED}.bed" \
    "${SAMPLE_COUNT}" \
    "${SNP_COUNT}" \
    "${COMBINED}.bin"

## Step 4.1. Prepare additional input files
PGEN_PREFIX="${DATA_DIR}/geno/chr%d"
createSnpInfoFiles.py "${PGEN_PREFIX}" "${DATA_DIR}"
computeGenoCounts.py "${PGEN_PREFIX}" "${SAMPLE_KEEP}" "${DATA_DIR}/geno"
echo "${SAMPLE_COUNT}" > "${DATA_DIR}/count.txt"
echo "${SNP_COUNT}" >> "${DATA_DIR}/count.txt"

## Step 4.2. Generate matrix blocks.
BLOCK_SIZE=8192
get_config_global() {
    grep "$1" "${CONFIG_DIR}/configGlobal.toml" | cut -d= -f2 | tr -d ' '
}
matrix_text2bin_blocks.py \
    "${DATA_DIR}" \
    "$(get_config_global geno_num_folds)" \
    "${BLOCK_SIZE}" \
    "${DATA_DIR}"

## Step 5. Update local configs.
echo "Updating config..."
sed -i "s|../${EXAMPLE_DATA_DIR}|${DATA_DIR}|g" "${CONFIG_DIR}/configLocal.Party${PID}.toml"

echo "Data preparation complete."
