import numpy as np
import sys
gcfile = sys.argv[1]
print("Processing file", gcfile)
x=np.loadtxt(gcfile, dtype=np.uint32)
print(x.shape)
x=x.transpose()
print(x.shape)
print(x.dtype)
x.tofile(gcfile + ".transpose.bin")
print("Done")
