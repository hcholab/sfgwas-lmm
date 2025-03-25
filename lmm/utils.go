package lmm

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	mpc_core "github.com/hhcho/mpc-core"
	"github.com/hhcho/sfgwas-lmm/mpc"

	"github.com/hhcho/sfgwas-lmm/crypto"

	"github.com/ldsec/lattigo/v2/ckks"
	"gonum.org/v1/gonum/mat"

	"encoding/binary"

	"go.dedis.ch/onet/v3/log"
)

func Float64frombytes(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	float := math.Float64frombits(bits)
	return float
}

func Float64bytes(float float64) []byte {
	bits := math.Float64bits(float)
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, bits)
	return bytes
}

func ReadFloatBin(filename string, nrow int, ncol int) *mat.Dense {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(file)

	buf := make([]byte, 8*nrow*ncol)
	if _, err := io.ReadFull(reader, buf); err != nil {
		log.Fatal(err)
	}
	bufFloat := make([]float64, nrow*ncol)
	//reads 8 bytes
	for i := 0; i < len(buf); i += 8 {
		bufFloat[i/8] = Float64frombytes(buf[i : i+8])
	}

	res := mat.NewDense(nrow, ncol, bufFloat)
	return res
}
func WriteFloatBin(X *mat.Dense, filename string) {
	file, err := os.Create(filename)
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	writer := bufio.NewWriter(file)
	r, c := X.Dims()
	buf := make([]byte, r*c*8)
	lenOfRow := 8 * c
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			floatBytes := Float64bytes(X.At(i, j))
			index := i*lenOfRow + j*8
			for k := 0; k < 8; k++ {
				buf[index+k] = floatBytes[k]
			}
		}
	}
	writer.Write(buf)

	writer.Flush()
}
func splitFolds(X *mat.Dense, foldSizes []int) ([]*mat.Dense, []*mat.Dense) {
	K := len(foldSizes)
	fmt.Println("K:", K)
	fmt.Println(foldSizes)
	X_fold := make([]*mat.Dense, K)
	_, c := X.Dims()
	runningSum := 0
	for k := 0; k < K; k++ {
		X_fold[k] = mat.DenseCopyOf(X.Slice(runningSum, runningSum+foldSizes[k], 0, c))
		runningSum += foldSizes[k]
	}
	if K == 1 {
		return X_fold, make([]*mat.Dense, K)
	}

	kminus := make([]*mat.Dense, K)
	for i := 0; i < K; i++ {
		stack := X_fold[0]
		start := 1
		if i == 0 {
			stack = X_fold[1]
			start = 2
		}
		for j := start; j < K; j++ {
			if j != i {
				r, c := stack.Dims()
				foldr, _ := X_fold[j].Dims()
				newStack := mat.NewDense(r+foldr, c, nil)
				newStack.Stack(stack, X_fold[j])
				stack = newStack
			}
		}
		kminus[i] = stack
	}
	return X_fold, kminus
}

func CalculateVariance(cps *crypto.CryptoParams, mpcObj *mpc.MPC, sqScaledSum crypto.CipherVector, mean crypto.CipherVector, N int, ddof int) crypto.CipherVector {
	sqScaledSum = mpcObj.Network.CollectiveBootstrapVec(cps, sqScaledSum, -1) //this is scaled
	squaredMean := crypto.CMult(cps, mean, mean)
	squaredMean = crypto.CMultConst(cps, squaredMean, float64(N)/math.Sqrt(float64(N-ddof)), false) //this is sum/N
	num := crypto.CSub(cps, sqScaledSum, squaredMean)                                               // might need to rescale in between
	scale := 1 / math.Sqrt(float64(N-ddof))
	res := crypto.CMultConst(cps, num, scale, false)
	return res
}

func sumStats(cps *crypto.CryptoParams, X crypto.CipherMatrix, vecLen int, scale float64) (crypto.CipherVector, crypto.CipherVector) {
	n := len(X)
	slots := cps.GetSlots()
	sumSqAllScaled := CZeros(cps, n)
	sumAll := CZeros(cps, n)
	maskClear := make([]float64, len(X[0])*slots)
	for i := 0; i < len(X[0])*slots; i++ {
		if i < vecLen {
			maskClear[i] = 1
		} else {
			maskClear[i] = 0
		}
	}
	mask, _ := crypto.EncodeFloatVector(cps, maskClear)
	for i := 0; i < n; i++ {
		Xmask := crypto.CPMult(cps, X[i], mask)
		sum := crypto.InnerSumAll(cps, Xmask)
		sq := crypto.CMult(cps, Xmask, Xmask)
		sqScaled := crypto.CMultConst(cps, sq, scale, false)
		sumSqScaled := crypto.InnerSumAll(cps, sqScaled)
		ctid := int(i / slots)
		slotid := i % slots

		sumMask := crypto.Mask(cps, sum, slotid, false)
		sumSqScaledMask := crypto.Mask(cps, sumSqScaled, slotid, false)
		sumAll[ctid] = crypto.Add(cps, sumAll[ctid], sumMask)
		sumSqAllScaled[ctid] = crypto.Add(cps, sumSqAllScaled[ctid], sumSqScaledMask)
	}
	return sumAll, sumSqAllScaled
}

func ComputeEtaMask(cps *crypto.CryptoParams, blockToChr []int, chr, B, R int) (crypto.CipherVector, bool) {
	mask := make([]float64, B*R)
	for i := 0; i < B; i++ {
		setVal := 0.0
		if blockToChr[i] != chr {
			setVal = 1.0
		}
		for j := 0; j < R; j++ {
			mask[i*R+j] = setVal
		}
	}
	isZero := true
	for i := 0; i < B*R; i++ {
		if mask[i] != 0 {
			isZero = false
			break
		}
	}
	res, _ := crypto.EncryptFloatVector(cps, mask)
	return res, isZero
}

func cipherToMat(cps *crypto.CryptoParams, X crypto.CipherMatrix, n int) *mat.Dense {
	columns := len(X)
	decr := crypto.DecryptFloatMatrix(cps, X, n)
	return mat.DenseCopyOf(mat.NewDense(columns, n, flattenDoubleArray(decr)).T())
}

func cipherToNetworkMat(cps *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherMatrix, n int) *mat.Dense {
	network := mpcObj.Network
	var y *mat.Dense
	for sourcePid := 1; sourcePid < network.GetNParty(); sourcePid++ {
		tmp := cipherToNetworkMatPid(cps, mpcObj, X, n, sourcePid)
		if sourcePid == mpcObj.GetPid() {
			y = tmp
		}
	}
	return y
}
func cipherToNetworkMatReal(cps *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherMatrix, n int) *mat.Dense {
	network := mpcObj.Network
	var y *mat.Dense
	for sourcePid := 1; sourcePid < network.GetNParty(); sourcePid++ {
		tmp := cipherToNetworkMatPidReal(cps, mpcObj, X, n, sourcePid)
		if sourcePid == mpcObj.GetPid() {
			y = tmp
		}
	}
	return y
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func cipherToNetworkMatPid(cps *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherMatrix, n int, pid int) *mat.Dense {
	limitCol, limitN := 5, 5
	ncol := min(limitCol, len(X))
	nelem := min(limitN, n)
	nelemCt := 1 + ((nelem - 1) / cps.GetSlots())
	if len(X) > 0 {
		nelemCt = min(len(X[0]), nelemCt)
	}
	X2 := make(crypto.CipherMatrix, ncol)
	for i := range X2 {
		X2[i] = X[i][:nelemCt]
	}
	decrPlain := mpcObj.Network.CollectiveDecryptMat(cps, X2, pid)
	decr := crypto.PlaintextToDense(cps, decrPlain, nelem)
	return decr
}

func cipherToNetworkMatPidReal(cps *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherMatrix, n int, pid int) *mat.Dense {
	ncol := len(X)
	nelem := n
	nelemCt := 1 + ((nelem - 1) / cps.GetSlots())
	if len(X) > 0 {
		nelemCt = min(len(X[0]), nelemCt)
	}
	X2 := make(crypto.CipherMatrix, ncol)
	for i := range X2 {
		X2[i] = X[i][:nelemCt]
	}
	decrPlain := mpcObj.Network.CollectiveDecryptMat(cps, X2, pid)
	decr := crypto.PlaintextToDense(cps, decrPlain, nelem)
	return decr
}

func matPrintReal(X mat.Matrix) {
	fa := mat.Formatted(X, mat.Prefix(""), mat.FormatPython())
	fmt.Printf("%#v\n", fa)
}

func matPrint(X mat.Matrix) {
	r, c := X.Dims()
	r = min(r, 5)
	c = min(c, 5)
	X2 := mat.NewDense(r, c, nil)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			X2.Set(i, j, X.At(i, j))
		}
	}
	fa := mat.Formatted(X2, mat.Prefix(""), mat.FormatPython())
	fmt.Printf("%#v\n", fa)
}

func compute_lambdas(h2s []float64, n float64) []float64 {
	lambdas := make([]float64, len(h2s))
	for i := 0; i < len(h2s); i++ {
		h2 := h2s[i]
		lambdas[i] = n * (1 - h2) / h2
	}
	return lambdas
}

func compute_h2s(R int) []float64 {
	h2s := make([]float64, R)
	for r := 0; r < R; r++ {
		h2s[r] = (1.0 / float64(R-1)) * float64(r)
	}
	h2s[0] = 0.01
	h2s[R-1] = 0.99
	return h2s
}

// func StackAllPartiesX(ap *AllParties) *mat.Dense {
// 	stack := ap.Parties[0].grm.snpData.data
// 	for i := 1; i < ap.P; i++ {
// 		newStack := mat.NewDense((i+1)*ap.N/ap.P, ap.M, nil)
// 		newStack.Stack(stack, ap.Parties[i].grm.snpData.data)
// 		stack = newStack
// 	}
// 	return stack
// }

func GenerateRandMatrix(r *rand.Rand, n int, m int) *mat.Dense {
	listX := make([]float64, n*m)
	for i := 0; i < n*m; i++ {
		listX[i] = float64(r.Intn(3))
	}
	X := mat.NewDense(n, m, listX)
	return X
}

func GenerateRandVector(r *rand.Rand, n int) *mat.VecDense {
	listY := make([]float64, n)
	for i := 0; i < n; i++ {
		listY[i] = float64(r.Intn(3))
	}
	y := mat.NewVecDense(n, listY)
	return y
}

func SumNAlongParties(ind int, n_per []int) int {
	sum := 0
	for j := 0; j < ind; j++ {
		sum += n_per[j]
	}
	return sum
}

func GenerateIdentity(delta float64, n int) *mat.DiagDense {
	identity := make([]float64, n)
	for i := 0; i < n; i++ {
		identity[i] = delta
	}
	I := mat.NewDiagDense(n, identity)
	return I
}

func GenerateOnes(delta float64, n int, m int) *mat.Dense {
	ones := make([]float64, n*n)
	for i := 0; i < n*m; i++ {
		ones[i] = delta
	}
	res := mat.NewDense(n, m, ones)
	return res
}

func CPDot(cryptoParams *crypto.CryptoParams, X crypto.CipherVector, Y crypto.PlainVector) *ckks.Ciphertext {
	innerProd := crypto.CPMult(cryptoParams, X, Y)
	cipher := crypto.InnerSumAll(cryptoParams, innerProd)
	return cipher
}
func CDot(cryptoParams *crypto.CryptoParams, X crypto.CipherVector, Y crypto.CipherVector) *ckks.Ciphertext {
	innerProd := crypto.CMult(cryptoParams, X, Y)
	cipher := crypto.InnerSumAll(cryptoParams, innerProd) // might be bad to have innersumall instead of innersum
	return cipher
}

func maxIntSlice(slice []int) int {
	out := slice[0]
	for i := 1; i < len(slice); i++ {
		if slice[i] > out {
			out = slice[i]
		}
	}
	return out
}

func sumIntSlice(slice []int) int {
	out := 0
	for i := range slice {
		out += slice[i]
	}
	return out
}

func readIntSliceFromFile(filename string, configname string, numLines int) []int {
	file, err := os.Open(filename)

	if err != nil {
		log.Fatalf("failed to open: %s defined by config %s", filename, configname)
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	out := make([]int, numLines)
	for i := 0; i < numLines; i++ {
		if !scanner.Scan() {
			log.Fatalf("not enough lines in %s: %d", filename, numLines)
		}

		out[i], err = strconv.Atoi(scanner.Text())
		if err != nil {
			log.Fatalf("parse error in %s: %s", filename, err.Error())
		}
	}

	if scanner.Scan() {
		log.Fatalf("too many lines in %s", filename)
	}

	file.Close()

	return out
}

func CipherTextDivideDummy(cryptoParams *crypto.CryptoParams, mpcObj *mpc.MPC, X *ckks.Ciphertext, Y *ckks.Ciphertext) *ckks.Ciphertext {
	Xvec := crypto.CipherVector{X}
	Yvec := crypto.CipherVector{Y}
	XP := crypto.DecryptFloatVector(cryptoParams, Xvec, 1)[:1]
	YP := crypto.DecryptFloatVector(cryptoParams, Yvec, 1)[:1]
	log.LLvl1(time.Now().Format(time.StampMilli), "cipherTextdivide")
	div := XP[0] / YP[0]
	res := crypto.EncryptFloat(cryptoParams, div)
	return res
}

func DummyPlaceInnerSum(cryptoParams *crypto.CryptoParams, X *ckks.Ciphertext) *ckks.Ciphertext {
	XP := crypto.DecryptFloat(cryptoParams, X)
	res := crypto.EncryptFloat(cryptoParams, XP)
	return res
}

// dummy
func CipherVectorSqrtInverseDummy(cryptoParams *crypto.CryptoParams, X crypto.CipherVector, n int) crypto.CipherVector {
	// log.LLvl1(time.Now().Format(time.StampMilli),"n int: ", n)
	XP := crypto.DecryptFloatVector(cryptoParams, X, n)
	// log.LLvl1(time.Now().Format(time.StampMilli),XP)
	for i := 0; i < len(XP); i++ {
		if XP[i] < 1e-8 {
			XP[i] = 0
		} else {
			XP[i] = math.Sqrt(XP[i])
		}
	}
	// log.LLvl1(time.Now().Format(time.StampMilli),XP)

	for i := 0; i < len(XP); i++ {
		if XP[i] < 1e-8 {
			XP[i] = 0
		} else {
			XP[i] = 1 / XP[i]
		}
	}
	log.LLvl1(time.Now().Format(time.StampMilli), "INVERSE STD")
	log.LLvl1(time.Now().Format(time.StampMilli), XP)

	res, _ := crypto.EncryptFloatVector(cryptoParams, XP)
	return res
}

func CipherVectorInnerProdSS(cryptoParams *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherVector, nelem int) mpc_core.RElem {
	rv := mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), X, mpcObj.GetHubPid(), 1+((nelem-1)/cryptoParams.GetSlots()), nelem)
	r, m := mpcObj.BeaverPartitionVec(rv)
	iprod := mpcObj.GetRType().Zero()
	for i := range r {
		iprod = iprod.Add(mpcObj.BeaverMult(r[i], m[i], r[i], m[i]))
	}
	iprod = mpcObj.BeaverReconstruct(iprod)
	iprod = mpcObj.Trunc(iprod, mpcObj.GetDataBits(), mpcObj.GetFracBits())
	return iprod
}

func AllocateAllResources(n, m int) ([]int, []int) {
	x := make([]int, m)
	counter := 0
	for i := 0; i < m; i++ {
		x[i] = n / m
		counter += x[i]
	}
	for i := 0; i < m-counter; i++ {
		x[i] += 1
	}
	y := make([]int, m)
	counter = 0
	for i := 0; i < len(x); i++ {
		y[i] = counter
		counter += x[i]
	}
	return x, y
}

func CipherVectorInnerProd2SS(cryptoParams *crypto.CryptoParams, mpcObj *mpc.MPC, X, Y crypto.CipherVector, nelem int) mpc_core.RElem {
	rv1 := mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), X, mpcObj.GetHubPid(), 1+((nelem-1)/cryptoParams.GetSlots()), nelem)
	rv2 := mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), Y, mpcObj.GetHubPid(), 1+((nelem-1)/cryptoParams.GetSlots()), nelem)
	iprod := mpcObj.SSMultMat(mpc_core.RMat{rv1}, mpc_core.RMat{rv2}.Transpose())[0][0]
	iprod = mpcObj.Trunc(iprod, mpcObj.GetDataBits(), mpcObj.GetFracBits())
	return iprod
}

func CipherVectorSqrtInverse(cryptoParams *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherVector, n int) crypto.CipherVector {
	pid := mpcObj.GetPid()
	rtype := mpcObj.GetRType().Zero()
	xSS := mpc_core.InitRVec(rtype.Zero(), n)
	if pid > 0 {
		xSS = mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), X, -1, len(X), n)
	}
	_, xInvSS := mpcObj.SqrtAndSqrtInverse(xSS)
	return mpcObj.SSToCVec(cryptoParams, xInvSS)
}

// TODO: Instead of processing each party's multiplication sequentially do it in parallel
func CMultWithRMatBlock(params *crypto.CryptoParams, mpcObj *mpc.MPC, cv crypto.CipherVector, rmList []mpc_core.RMat, nElemPerCtx int) []crypto.CipherVector {
	pid := mpcObj.GetPid()
	C := nElemPerCtx
	nCtx := len(cv)
	rtype := mpcObj.GetRType()

	// log.LLvl1("CMultWithRMatBlock dims:", "C", C, "nCtx", nCtx, "len(rmList)", len(rmList))

	for i := range rmList {
		if nCtx*C != len(rmList[i]) {
			panic("Number of rows in RMat does not match length of CipherVector times nElemPerCtx")
		}
		if len(rmList[i]) != len(rmList[i][0]) {
			panic("RMat is not square")
		}
	}

	rvec := make([]mpc_core.RVec, len(rmList))
	for p := range rvec {
		rvec[p] = mpc_core.InitRVec(rtype, nCtx*C)
	}

	if pid > 0 {
		shift := 0
		for i := range cv {
			vList := mpcObj.CVecToSSConcat(params, mpcObj.GetRType(), crypto.CipherVector{cv[i]}, 1, C)
			for p := range vList {
				v := vList[p]
				for j := range v {
					rvec[p][shift+j] = v[j]
				}
			}
			shift += C
		}
	}

	outSS := make([]mpc_core.RVec, len(rvec))
	//mpc_core.RMat{rvec[p]} needs to be transposed to

	for p := range rvec {
		// outSS[p] = mpcObj.SSMultMat(rmList[p], mpc_core.RMat{rvec[p]}.Transpose()).Transpose()[0] //swap order for left SS mult cvec
		outSS[p] = mpcObj.SSMultMat(mpc_core.RMat{rvec[p]}, rmList[p])[0] //swap order for left SS mult cvec
		outSS[p] = mpcObj.TruncVec(outSS[p], mpcObj.GetDataBits(), mpcObj.GetFracBits())
	}

	out := make([]crypto.CipherVector, len(outSS))
	for p := range out {
		out[p] = make(crypto.CipherVector, nCtx)
	}
	if pid > 0 {
		shift := 0
		for i := range cv {
			for p := range out {
				out[p][i] = mpcObj.SStoCiphertext(params, outSS[p][shift:shift+C])
			}
			shift += C
		}
	}

	return out
}

// Instead of processing each party's multiplication sequentially do it in parallel by batching
func CMultWithRMatBlockParallel(params *crypto.CryptoParams, mpcObj *mpc.MPC, cv crypto.CipherVector, rmList []mpc_core.RMat, nElemPerCtx int) []crypto.CipherVector {
	pid := mpcObj.GetPid()
	C := nElemPerCtx
	nCtx := len(cv)
	rtype := mpcObj.GetRType()

	// log.LLvl1("CMultWithRMatBlock dims:", "C", C, "nCtx", nCtx, "len(rmList)", len(rmList))

	for i := range rmList {
		if nCtx*C != len(rmList[i]) {
			panic("Number of rows in RMat does not match length of CipherVector times nElemPerCtx")
		}
		if len(rmList[i]) != len(rmList[i][0]) {
			panic("RMat is not square")
		}
	}

	rvec := make([]mpc_core.RVec, len(rmList))
	for p := range rvec {
		rvec[p] = mpc_core.InitRVec(rtype, nCtx*C)
	}

	if pid > 0 {
		cm := mpcObj.Network.BroadcastCVecConcat(params, cv, nCtx)
		cmFlat := make(crypto.CipherMatrix, len(cm)*nCtx)
		for i := range cm {
			for j := 0; j < nCtx; j++ {
				cmFlat[nCtx*i+j] = crypto.CipherVector{cm[i][j]}
			}
		}

		rm := mpcObj.CMatToSS(params, rtype, cmFlat, -1, len(cmFlat), 1, C)

		for i := range rvec {
			for j := 0; j < nCtx; j++ {
				for k := 0; k < C; k++ {
					rvec[i][C*j+k] = rm[nCtx*i+j][k]
				}
			}
		}
	}

	outSS := make([]mpc_core.RVec, len(rvec))
	//mpc_core.RMat{rvec[p]} needs to be transposed too

	rvecMat := make([]mpc_core.RMat, len(rvec))
	for i := range rvecMat {
		rvecMat[i] = mpc_core.RMat{rvec[i]}
	}

	outSSMat := mpcObj.SSMultMatParallel(rvecMat, rmList)
	outSSMatFlat := make(mpc_core.RMat, len(rvec))
	for i := range outSSMatFlat {
		outSSMatFlat[i] = outSSMat[i][0]
	}
	outSS = mpcObj.TruncMat(outSSMatFlat, mpcObj.GetDataBits(), mpcObj.GetFracBits())

	out := make([]crypto.CipherVector, len(outSS))
	for p := range out {
		out[p] = make(crypto.CipherVector, nCtx)
	}

	if pid > 0 {
		outSSFlat := make(mpc_core.RMat, len(rvec)*nCtx) // nParty * nCtx by C
		for i := range rvec {
			for j := 0; j < nCtx; j++ {
				outSSFlat[nCtx*i+j] = outSS[i][C*j : C*(j+1)]
			}
		}

		cm := mpcObj.SSToCMat(params, outSSFlat)

		for i := range out {
			for j := range out[i] {
				out[i][j] = cm[nCtx*i+j][0]
			}
		}
	}

	return out
}

func CipherTextDivide(cryptoParams *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherVector, Y crypto.CipherVector, n int) crypto.CipherVector {
	pid := mpcObj.GetPid()
	rtype := mpcObj.GetRType().Zero()
	xSS := mpc_core.InitRVec(rtype.Zero(), n)
	ySS := mpc_core.InitRVec(rtype.Zero(), n)

	if pid > 0 {
		xSS = mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), X, -1, len(X), n)
		ySS = mpcObj.CVecToSS(cryptoParams, mpcObj.GetRType(), X, -1, len(X), n)
	}
	resSS := mpcObj.Divide(xSS, ySS)
	return mpcObj.SSToCVec(cryptoParams, resSS)
}

func CPCompare(cryptoParams *crypto.CryptoParams, X *ckks.Ciphertext, Y float64, op string) bool {
	XP := crypto.DecryptFloat(cryptoParams, X)
	switch op {
	case "<":
		return XP < Y
	case ">":
		return XP > Y
	default:
		panic("Not a valid op")
	}
}
func CCompare(cryptoParams *crypto.CryptoParams, X *ckks.Ciphertext, Y *ckks.Ciphertext, op string) bool {
	XP := crypto.DecryptFloat(cryptoParams, X)
	YP := crypto.DecryptFloat(cryptoParams, Y)

	switch op {
	case "<":
		return XP < YP
	case ">":
		return XP > YP
	default:
		panic("Not a valid op")
	}
}
func matrixSquare(cps *crypto.CryptoParams, x crypto.CipherMatrix) crypto.CipherMatrix {
	for i := 0; i < len(x); i++ {
		x[i] = crypto.CMult(cps, x[i], x[i])
	}
	return x
}

func matrixAddCols(cps *crypto.CryptoParams, x crypto.CipherMatrix) crypto.CipherVector {
	res := crypto.CopyEncryptedVector(x[0])
	for i := 1; i < len(x); i++ {
		res = crypto.CAdd(cps, res, x[i])
	}
	return res
}

func flattenDoubleArray(x [][]float64) []float64 {
	n := len(x)
	m := len(x[0])
	newX := make([]float64, n*m)
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			newX[i*m+j] = x[i][j]
		}
	}
	return newX
}

func logDeltaToH2(delta float64) float64 {
	return 1 / (math.Exp(delta) + 1)
}

func h2ToLogDelta(h2 float64) float64 {
	return math.Log((1 - h2) / h2)
}

func CZeros(cps *crypto.CryptoParams, n int) crypto.CipherVector {
	tmp := make([]float64, n)
	for i := 0; i < n; i++ {
		tmp[i] = 0
	}
	res, _ := crypto.EncryptFloatVector(cps, tmp)
	return res
}

func CRands(cps *crypto.CryptoParams, n int) crypto.CipherVector {
	tmp := make([]float64, n)
	for i := 0; i < n; i++ {
		tmp[i] = rand.NormFloat64()
	}
	res, _ := crypto.EncryptFloatVector(cps, tmp)
	return res
}

func CMatSub(cryptoParams *crypto.CryptoParams, X crypto.CipherMatrix, Y crypto.CipherMatrix) crypto.CipherMatrix {
	res := make(crypto.CipherMatrix, len(X))
	for i := 0; i < len(X); i++ {
		res[i] = crypto.CSub(cryptoParams, X[i], Y[i])
	}
	return res
}
func CMatAdd(cryptoParams *crypto.CryptoParams, X crypto.CipherMatrix, Y crypto.CipherMatrix) crypto.CipherMatrix {
	res := make(crypto.CipherMatrix, len(X))
	for i := 0; i < len(X); i++ {
		res[i] = crypto.CAdd(cryptoParams, X[i], Y[i])
	}
	return res
}

func CMatMultConst(cryptoParams *crypto.CryptoParams, X crypto.CipherMatrix, a float64) crypto.CipherMatrix {
	res := make(crypto.CipherMatrix, len(X))
	for i := 0; i < len(X); i++ {
		res[i] = crypto.CMultConst(cryptoParams, X[i], a, false)
	}
	return res
}

func maskFirstPlaces(cps *crypto.CryptoParams, X crypto.CipherVector, n int) crypto.CipherVector {
	slots := cps.GetSlots()
	totalVecLen := len(X) * slots
	maskClear := make([]float64, totalVecLen)
	for i := 0; i < totalVecLen; i++ {
		if i < n {
			maskClear[i] = 1
		} else {
			maskClear[i] = 0
		}
	}
	maskEncr, _ := crypto.EncryptFloatVector(cps, maskClear)
	return crypto.CMult(cps, X, maskEncr)
}

func dummyEncryptAccurately(cps *crypto.CryptoParams, X *mat.Dense, scale float64) crypto.CipherMatrix {
	n, m := X.Dims()
	scaled := mat.NewDense(n, m, nil)
	scaled.Scale(scale, X)
	encr := crypto.EncryptDense(cps, scaled)
	return CMatMultConst(cps, encr, 1/scale)
}

func appendLists(x, y []float64) []float64 {
	out := make([]float64, len(x)+len(y))
	for i := 0; i < len(x); i++ {
		out[i] = x[i]
	}
	for i := 0; i < len(y); i++ {
		out[i+len(x)] = y[i]
	}
	return out
}
