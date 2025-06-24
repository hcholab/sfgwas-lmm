#!/usr/bin/env python3

# converts a genotype matrix file provided as a text file
# into a binary file with 1 byte per element
# assumes elements are integers (e.g. 0,1,2,-1)
# and uses int8 for output

import math
import os
import sys

import numpy as np

# Assumes pos_qc.txt includes chromosome ID in the first column
# Variants should be sorted in the order of chromosomes (each chrom forms a contiguous block)

# per-party directory, like example_data/party1
# input_dir + "/combined.bin"/"count.txt"/"snp_pos.txt" should exist
input_dir = sys.argv[1]

counts = [int(line) for line in open(os.path.join(input_dir, "count.txt"))]
nrows = counts[0]
ncols = counts[1]

nfolds = int(sys.argv[2])
ncols_per_block = int(sys.argv[3])  # 8192
output_dir = sys.argv[4]  # per-party

# find chrids
chr_ids = [line.split()[0] for line in open(os.path.join(input_dir, "snp_pos.txt"))]
ind = 0
prev = None
colchrinds = []
for ch in chr_ids:
    if prev != ch:
        colchrinds.append(ind)
    prev = ch
    ind += 1
colchrinds.append(ind)
numchr = len(colchrinds) - 1

# create paths
# ncolblock = math.ceil(float(ncol) / float(ncols_per_block))
ncolblock = 0
for ch in range(numchr):
    ncolblock += int(
        math.ceil(float(colchrinds[ch + 1] - colchrinds[ch]) / float(ncols_per_block))
    )


def get_block_inds(ntot, nblock):
    blockinds = [0] * (nblock + 1)
    perblock = int(ntot / nblock)
    nrem = ntot - perblock * nblock
    for i in range(nblock):
        count = perblock
        if i < nrem:
            count += 1
        blockinds[i + 1] = blockinds[i] + count
    return blockinds


def write_block_inds(outfile, blockinds):
    with open(outfile, 'wt') as f:
        for i in range(len(blockinds) - 1):
            f.write(str(blockinds[i + 1] - blockinds[i]) + "\n")


outfile = []
for k in range(nfolds):
    arr = [
        os.path.join(
            output_dir,
            f"fold{k+1}.{j}.bin",
        )
        for j in range(ncolblock)
    ]
    outfile.append(arr)
print("ncolblock", ncolblock)

foldsizes = np.zeros(nfolds)
foldpartyinds = None
rowpartyinds = get_block_inds(nrows, nfolds)
for f in range(nfolds):
    foldsizes[f] = rowpartyinds[f + 1] - rowpartyinds[f]
foldpartyinds = rowpartyinds
print("foldsizes", foldsizes)
print("rowpartyinds", rowpartyinds)

txt = "\n".join([str(int(v)) for v in foldsizes])
with open(os.path.join(output_dir, f"foldSizes.txt"), 'wt') as f:
    f.write(txt)

block2chr = []

colblockinds = np.zeros(ncolblock + 1, dtype=int)
ind = 1
for ch in range(numchr):
    n2 = colchrinds[ch + 1] - colchrinds[ch]
    nblock = int(math.ceil(float(n2) / float(ncols_per_block)))
    for b in range(nblock):
        colblockinds[ind] = colblockinds[ind - 1] + ncols_per_block
        ind += 1
        block2chr.append(str(ch))
    colblockinds[ind - 1] = colchrinds[ch + 1]

print("chr inds")
print(len(colchrinds))
print(colchrinds)
print(np.array(colchrinds[1:]) - np.array(colchrinds[0:-1]))

print("snp block inds")
print(len(colblockinds))
print(colblockinds)
print(colblockinds[1:] - colblockinds[0:-1])

# create block files
write_block_inds(os.path.join(output_dir, "blockSizes.txt"), colblockinds)
with open(os.path.join(output_dir, "blockToChrom.txt"), 'wt') as f:
    f.write("\n".join(block2chr) + "\n")

with open(os.path.join(input_dir, "combined.bin"), 'rb') as f:
    arr = np.fromfile(f, dtype=np.int8)
    arr = np.reshape(arr, (nrows, ncols))
    print("shape", arr.shape)
    for k in range(nfolds):
        for b in range(ncolblock):
            print("processing ", outfile[k][b])
            with open(outfile[k][b], 'ab') as of:
                arr[
                    int(foldpartyinds[k]) : int(foldpartyinds[k + 1]),
                    colblockinds[b] : colblockinds[b + 1],
                ].tofile(of)
