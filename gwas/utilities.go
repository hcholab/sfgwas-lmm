package gwas

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.dedis.ch/onet/v3/log"

	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/hhcho/sfgwas-lmm/mpc"
	"gonum.org/v1/gonum/mat"
)

// Reads in a binary file containing 6 vectors of length m (# of SNPs):
// ref allele count (AC), alt AC, hom-ref genotype count (GC), het GC,
// hom-alt GC, missing sample count.
// Each value is encoded as uint32 in little endian format
func ReadGenoStatsFromFile(filename string, m int) (ac, gc [][]uint32, miss []uint32) {
	nstats := 6

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(file)

	out := make([][]uint32, nstats)
	buf := make([]byte, 4*m) // 4 bytes per number
	for s := 0; s < nstats; s++ {
		out[s] = make([]uint32, m)

		if _, err := io.ReadFull(reader, buf); err != nil {
			log.Fatal(err)
		}

		for i := range out[s] {
			out[s][i] = binary.LittleEndian.Uint32(buf[4*i:])
		}
	}

	gc = out[:3]

	// TODO: remove allele counts from file as they are redundant
	for i := range out[3] {
		out[3][i] = out[1][i] + 2*out[0][i]
		out[4][i] = out[1][i] + 2*out[2][i]
	}
	ac = out[3:5]

	miss = out[5]

	return
}

func TransposeMatrixFile(inputFile string, nrows, ncols int, outputFile string) {
	cmd := exec.Command("/bin/sh", "../scripts/transposeMatrix.sh", inputFile, strconv.Itoa(nrows), strconv.Itoa(ncols), outputFile)
	cout, e := cmd.CombinedOutput()
	fmt.Print(string(cout))
	if e != nil {
		log.Fatal(e)
	}
}

func Min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}
func Mod(n int, modulus int) int {
	n = n % modulus
	if n < 0 {
		n = n + modulus
	}
	return n
}

func LoadCacheFromFile(cps *crypto.CryptoParams, filename string) crypto.CipherMatrix {
	delim := ','

	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	defer f.Close()
	// See how we can read strings and parse them
	c := csv.NewReader(f)
	c.Comma = delim
	text, err := c.ReadAll()

	columns := c.FieldsPerRecord
	lines := len(text)

	data := make([][]float64, lines)

	for i := 0; i < lines; i++ {
		data[i] = make([]float64, columns)

		for j := 0; j < columns; j++ {
			data[i][j], err = strconv.ParseFloat(text[i][j], 64)
		}
	}

	res, _, _, _ := crypto.EncryptFloatMatrixRow(cps, data)
	return res
}

func LoadMatDenseCacheFromFile(filename string) *mat.Dense {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	var res mat.Dense

	defer f.Close()
	res.UnmarshalBinaryFrom(f)
	if err != nil {
		panic(err)
	}
	return &res
}

func LoadMatrixFromFile(filename string, delim rune) *mat.Dense {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	// See how we can read strings and parse them
	c := csv.NewReader(f)
	c.Comma = delim
	text, err := c.ReadAll()

	columns := c.FieldsPerRecord
	lines := len(text)

	data := make([]float64, columns*lines)

	for i := 0; i < lines; i++ {
		for j := 0; j < columns; j++ {
			data[i*columns+j], err = strconv.ParseFloat(text[i][j], 64)
		}
	}

	return mat.NewDense(lines, columns, data)
}

func LoadSNPPositionFile(filename string, delim rune) []uint64 {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	c := csv.NewReader(f)
	c.Comma = delim
	text, err := c.ReadAll()

	lines := len(text)

	data := make([]uint64, lines)

	for i := 0; i < lines; i++ {
		chrom, err := strconv.ParseUint(text[i][0], 10, 64)
		if err != nil {
			panic(err)
		}

		pos, err := strconv.ParseUint(text[i][1], 10, 64)
		if err != nil {
			panic(err)
		}

		data[i] = chrom*1e9 + pos
	}

	return data
}

func SaveMatrixToFile(cps *crypto.CryptoParams, mpcObj *mpc.MPC, cm crypto.CipherMatrix, nElemCol int, sourcePid int, filename string) {
	pid := mpcObj.GetPid()
	if pid == 0 {
		return
	}

	pm := mpcObj.Network.CollectiveDecryptMat(cps, cm, sourcePid)

	if pid == sourcePid || (sourcePid < 0 && pid == mpcObj.GetHubPid()) {
		M := mat.NewDense(len(cm), nElemCol, nil)
		for i := range pm {
			M.SetRow(i, crypto.DecodeFloatVector(cps, pm[i])[:nElemCol])
		}

		f, err := os.Create(filename)

		if err != nil {
			panic(err)
		}

		defer f.Close()

		rows, cols := M.Dims()

		for row := 0; row < rows; row++ {
			line := make([]string, cols)
			for col := 0; col < cols; col++ {
				line[col] = fmt.Sprintf("%.6e", M.At(row, col))
			}

			f.WriteString(strings.Join(line, ",") + "\n")
		}

		f.Sync()

		log.LLvl1("Saved data to", filename)

	}

}

func GenerateFName(fname string, p, k, b int) string {
	res := "block_" + strconv.Itoa(b) + "/" + fname + strconv.Itoa(p) + "_" + strconv.Itoa(k) + "_" + strconv.Itoa(b) + ".txt"
	return res
}

func SaveMatDenseToFile(mpcObj *mpc.MPC, sourcePid int, x *mat.Dense, filename string) {
	pid := mpcObj.GetPid()
	if pid == 0 {
		return
	}
	if pid == sourcePid || (sourcePid < 0 && pid == mpcObj.GetHubPid()) {
		file, err := os.Create(filename)
		defer file.Close()
		if err != nil {
			log.Fatal(err)
		}

		writer := bufio.NewWriter(file)

		_, err = x.MarshalBinaryTo(writer)
		if err != nil {
			log.Fatal(err)
		}

		writer.Flush()
		log.LLvl1("Saved data to", filename)
	}
}

func SaveFloatVectorToFile(filename string, x []float64) {
	file, err := os.Create(filename)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	writer := bufio.NewWriter(file)

	for i := range x {
		writer.WriteString(fmt.Sprintf("%.6e\n", x[i]))
	}

	writer.Flush()
}
