package gwas

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"gonum.org/v1/gonum/mat"
)

type GenoFileStream struct {
	filename  string
	file      *os.File
	reader    *bufio.Reader
	numRows   uint64
	numCols   uint64
	lineCount uint64
	buf       []byte

	filtRows []bool
	filtCols []bool

	missingColReplace []float64
	missingRowReplace []float64

	filtNumRow uint64
	filtNumCol uint64

	replaceMissing bool
}

func NewGenoFileStream(filename string, numRow, numCol uint64, replaceMissing bool) *GenoFileStream {
	file, err := os.Open(filename)

	if err != nil {
		panic(err)
	}

	return &GenoFileStream{
		filename:          filename,
		buf:               make([]byte, numCol),
		numRows:           numRow,
		numCols:           numCol,
		reader:            bufio.NewReader(file),
		lineCount:         0,
		filtNumRow:        0,
		filtNumCol:        0,
		filtRows:          nil,
		filtCols:          nil,
		missingColReplace: nil,
		missingRowReplace: nil,
		replaceMissing:    replaceMissing,
	}
}
func (gfs *GenoFileStream) readRow() []float64 {
	if gfs.CheckEOF() {
		return nil
	}

	_, err := io.ReadFull(gfs.reader, gfs.buf)
	if err != nil {
		panic(err)
	}

	var intBuf []float64
	if gfs.filtCols != nil {
		intBuf = make([]float64, gfs.filtNumCol)
	} else {
		intBuf = make([]float64, len(gfs.buf))
	}

	idx := 0
	for i := range gfs.buf {
		if gfs.filtCols == nil || gfs.filtCols[i] {
			intBuf[idx] = float64(int8(gfs.buf[i]))
			if gfs.replaceMissing && intBuf[idx] < 0 { // replace missing with zero
				if gfs.missingColReplace != nil {
					intBuf[idx] = gfs.missingColReplace[idx]
				} else if gfs.missingRowReplace != nil {
					intBuf[idx] = gfs.missingRowReplace[gfs.lineCount]
				} else {
					intBuf[idx] = 0
				}
			}
			idx++
		}
	}

	gfs.lineCount++

	return intBuf
}

func (gfs *GenoFileStream) Reset() {
	var err error
	if gfs.file == nil {
		gfs.file, err = os.Open(gfs.filename)
	} else {
		_, err = gfs.file.Seek(0, io.SeekStart)
	}

	if err != nil {
		panic(err)
	}

	gfs.reader = bufio.NewReader(gfs.file)
	gfs.lineCount = 0
}

func (gfs *GenoFileStream) NumRows() uint64 {
	return gfs.numRows
}

func (gfs *GenoFileStream) NumCols() uint64 {
	return gfs.numCols
}

func (gfs *GenoFileStream) NumRowsToKeep() uint64 {
	if gfs.filtRows == nil {
		return gfs.NumRows()
	}
	return gfs.filtNumRow
}

func (gfs *GenoFileStream) NumColsToKeep() uint64 {
	if gfs.filtCols == nil {
		return gfs.NumCols()
	}
	return gfs.filtNumCol
}

func (gfs *GenoFileStream) CheckEOF() bool {
	if gfs.lineCount >= gfs.numRows {
		if gfs.file != nil {
			gfs.file.Close()
		}
		gfs.file = nil
		gfs.reader = nil

		return true
	}

	return false
}

func (gfs *GenoFileStream) NextRow() []float64 {
	if gfs.CheckEOF() {
		return nil
	}

	if gfs.filtRows != nil {
		for gfs.lineCount < uint64(len(gfs.filtRows)) && !gfs.filtRows[gfs.lineCount] {
			gfs.readRow()
		}
	}

	return gfs.readRow()
}

func (gfs *GenoFileStream) UpdateRowFilt(a []bool) int {
	if len(a) != int(gfs.NumRowsToKeep()) {
		panic("Invalid length of input array")
	}

	if gfs.filtRows == nil {
		gfs.filtRows = make([]bool, gfs.numRows)
		for i := range gfs.filtRows {
			gfs.filtRows[i] = true
		}
	}

	sum := 0
	idx := 0
	for i := range gfs.filtRows {
		if gfs.filtRows[i] {
			gfs.filtRows[i] = gfs.filtRows[i] && a[idx]
			idx++
			if gfs.filtRows[i] {
				sum++
			}
		}
	}

	gfs.filtNumRow = uint64(sum)
	return sum
}

func (gfs *GenoFileStream) UpdateColFilt(a []bool) int {
	if len(a) != int(gfs.NumColsToKeep()) {
		panic("Invalid length of input array")
	}

	if gfs.filtCols == nil {
		gfs.filtCols = make([]bool, gfs.numCols)
		for i := range gfs.filtCols {
			gfs.filtCols[i] = true
		}
	}

	sum := 0
	idx := 0
	for i := range gfs.filtCols {
		if gfs.filtCols[i] {
			gfs.filtCols[i] = gfs.filtCols[i] && a[idx]
			idx++
			if gfs.filtCols[i] {
				sum++
			}
		}
	}

	gfs.filtNumCol = uint64(sum)
	return sum
}

func (gfs *GenoFileStream) ColFilt() []bool {
	return gfs.filtCols
}

func (gfs *GenoFileStream) RowFilt() []bool {
	return gfs.filtRows
}

func (gfs *GenoFileStream) ColMissingReplace() []float64 {
	return gfs.missingColReplace
}

func (gfs *GenoFileStream) RowMissingReplace() []float64 {
	return gfs.missingRowReplace
}

func (gfs *GenoFileStream) LineCount() uint64 {
	return gfs.lineCount
}

func (gfs *GenoFileStream) SetRowMissingReplace(a []float64) {
	if a != nil && len(a) != int(gfs.numRows) {
		panic("Invalid length of input array")
	}
	gfs.missingRowReplace = a
	gfs.missingColReplace = nil
}
func (gfs *GenoFileStream) SetColMissingReplace(a []float64) {
	if a != nil && len(a) != int(gfs.numCols) {
		panic("Invalid length of input array")
	}
	gfs.missingColReplace = a
	gfs.missingRowReplace = nil
}

func (gfs *GenoFileStream) ClearRowFilt() {
	gfs.filtRows = make([]bool, gfs.numRows)
	for i := range gfs.filtRows {
		gfs.filtRows[i] = true
	}
	fmt.Println("Before filtNumRow", gfs.filtNumRow, gfs.numRows)
	gfs.filtNumRow = gfs.numRows
	fmt.Println("Set filtNumRow", gfs.filtNumRow)
}

func (gfs *GenoFileStream) ToMatDense() *mat.Dense {
	gfs.Reset()
	numRows := int(gfs.NumRows())
	numCols := int(gfs.NumCols())
	A := mat.NewDense(numRows, numCols, nil)
	counter := 0
	for i := 0; i < numRows; i++ {
		row := gfs.NextRow()
		rowFloat := row
		A.SetRow(counter, rowFloat)
		counter++
	}
	return A
}
