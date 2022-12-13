#!/bin/sh
INPUT_BFILE_PREFIX=$1
plink2 --threads 1 --bfile ${INPUT_BFILE_PREFIX} --geno-counts --out ${INPUT_BFILE_PREFIX}_tmp
awk 'BEGIN{OFS="\t"}{if (NR>1) print $5,$6,$7,$8,$9,$10}'  ${INPUT_BFILE_PREFIX}_tmp.gcount > ${INPUT_BFILE_PREFIX}.gcount
python geno_count_to_bin.py ${INPUT_BFILE_PREFIX}.gcount
