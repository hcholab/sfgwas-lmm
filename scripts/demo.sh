#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  local sig=$(($? - 128))
  echo "Caught $(kill -l $sig) signal. Killing all background processes and exiting..."
  kill "$(jobs -p)" 2>/dev/null || true
}

trap cleanup INT TERM

BASE_DIR=$(dirname "$(dirname "$0")")
EXAMPLE_DATA="${BASE_DIR}/example_data"
SCRIPTS_DIR="${BASE_DIR}/scripts"
TEMP_DIR="${BASE_DIR}/tmp"
OUTPUT_DIR="${BASE_DIR}/output"

mkdir -p "${TEMP_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo "Preparing data for tests..."

# Process data for each party
for party in 1 2; do
    PARTY_DIR="${EXAMPLE_DATA}/party${party}"
    GENO_DIR="${PARTY_DIR}/geno"

    echo "Processing data for party ${party}..."

    # Convert PGEN files to PLINK1.9 BED format
    for chr in {1..22}; do
        echo "Converting chromosome ${chr} to BED format..."
        "${BASE_DIR}/plink2" --make-bed \
            --pfile "${GENO_DIR}/chr${chr}" \
            --out "${TEMP_DIR}/party${party}_chr${chr}"
    done

    #  Merge BED files
    echo "Merging BED files for party ${party}..."
    MERGE_LIST="${TEMP_DIR}/party${party}_merge_list.txt"
    for chr in {2..22}; do
        echo "${TEMP_DIR}/party${party}_chr${chr}" >> "${MERGE_LIST}"
    done
    COMBINED="${TEMP_DIR}/party${party}_combined"
    "${BASE_DIR}/plink" --make-bed \
        --bfile "${TEMP_DIR}/party${party}_chr1" \
        --merge-list "${MERGE_LIST}" \
        --out "${COMBINED}"

    # Get sample and SNP counts
    SAMPLE_COUNT=$(wc -l < "${COMBINED}.fam")
    SAMPLE_COUNT=$((SAMPLE_COUNT))
    SNP_COUNT=$(wc -l < "${COMBINED}.bim")
    SNP_COUNT=$((SNP_COUNT))

    echo "Party ${party} has ${SAMPLE_COUNT} samples and ${SNP_COUNT} SNPs"

    # Convert to binary format
    echo "Converting to binary format for party ${party}..."
    "${SCRIPTS_DIR}/plinkBedToBinary.py" \
            "${COMBINED}.bed" \
            "${SAMPLE_COUNT}" \
            "${SNP_COUNT}" \
            "${COMBINED}_binary.bin"

    # Create SNP info files
    echo "Creating SNP info files for party ${party}..."

    # Create chrom_sizes.txt (if not already exists)
    if [ ! -f "${PARTY_DIR}/chrom_sizes.txt" ]; then
        echo "Generating chrom_sizes.txt..."
        for chr in {1..22}; do
            SNP_COUNT_CHR=$(grep -c "^${chr}\s" "${COMBINED}.bim" || echo "0")
            echo "${chr} ${SNP_COUNT_CHR}" >> "${PARTY_DIR}/chrom_sizes.txt"
        done
    fi

    # Create snp_ids.txt (if not already exists)
    if [ ! -f "${PARTY_DIR}/snp_ids.txt" ]; then
        echo "Generating snp_ids.txt..."
        awk '{print $2}' "${COMBINED}.bim" > "${PARTY_DIR}/snp_ids.txt"
    fi

    # Create snp_pos.txt (if not already exists)
    if [ ! -f "${PARTY_DIR}/snp_pos.txt" ]; then
        echo "Generating snp_pos.txt..."
        awk '{print $1 "\t" $4}' "${COMBINED}.bim" > "${PARTY_DIR}/snp_pos.txt"
    fi

    # Precompute genotype counts
    if [ ! -f "${PARTY_DIR}/all.gcount.transpose.bin" ]; then
        echo "Precomputing genotype counts for party ${party}..."
        # Run plink2 geno-counts
        "${BASE_DIR}/plink2" \
        --bfile "${COMBINED}" \
               --geno-counts cols=chrom,pos,ref,alt,homref,refalt,homalt,hethap,missing \
               --out "${TEMP_DIR}/party${party}_gcount"

        # Extract relevant columns (allele, genotype, and missingness counts)
        awk 'BEGIN{OFS="\t"}{if (NR>1) print $5,$6,$7,$8,$9,$10}' \
            "${TEMP_DIR}/party${party}_gcount.gcount" > "${TEMP_DIR}/party${party}.gcount"

        # Convert to binary format
        # This assumes geno_count_to_bin.py script exists and works as expected
        python3 "${SCRIPTS_DIR}/geno_count_to_bin.py" "${TEMP_DIR}/party${party}.gcount"

        # Move the output file to the party directory
        mv "${TEMP_DIR}/party${party}.gcount.transpose.bin" "${PARTY_DIR}/all.gcount.transpose.bin"
    fi

    # Generate block files (if needed)
    # This step would use matrix_text2bin_blocks.py but requires specific parameters
    # We'll skip this for now as it depends on specific input structure
done

rm -rf "${TEMP_DIR}"

echo "Data preparation complete. Running tests..."

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
