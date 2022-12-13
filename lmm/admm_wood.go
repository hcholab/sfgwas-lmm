package lmm

import (
	"math"
	"strconv"
	"time"

	"github.com/hhcho/sfgwas-lmm/mpc"

	mpc_core "github.com/hhcho/mpc-core"

	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/hhcho/sfgwas-lmm/gwas"
	"gonum.org/v1/gonum/mat"

	"go.dedis.ch/onet/v3/log"
)

const CONTINUE = 1
const STOP = 0

type ADMM_Wood struct {
	general *gwas.ProtocolInfoLMM
	cps     *crypto.CryptoParams
	mpcObj  *mpc.MPC
	mpcObjs *mpc.ParallelMPC
	P       int //number of parties
	C       int //number of Cov
	T       int
	N       int
	rho     float64
	block   int
	fold    int

	ScaledAinv      *mat.Dense
	ScaledAinvCache gwas.PlainMatrixDiagCache
	b               crypto.CipherVector

	ScaledSX_iTZ_iCache crypto.PlainMatrix
	Z_iTZ_iZTZinv       crypto.CipherMatrix
	AinvSX_iTZ_iCache   crypto.PlainMatrix
	ScaledSXTZAll       crypto.CipherMatrix

	U               crypto.CipherMatrix
	V               crypto.CipherMatrix
	ScaledGinvSSAll []mpc_core.RMat

	X          crypto.CipherVector // local
	Nu         crypto.CipherVector // diff
	Z          crypto.CipherVector // global
	XBarminusZ crypto.CipherVector
	// ScaledXTZCache    crypto.PlainMatrix

}

//each param is required
type ADMMParams struct {
	general        *gwas.ProtocolInfoLMM
	cps            *crypto.CryptoParams
	mpcObj         *mpc.MPC
	mpcObjs        *mpc.ParallelMPC
	ATA            *mat.Dense
	ScaledX_iTZ_i  *mat.Dense
	ScaledXTZAll   crypto.CipherMatrix
	Z_iTZ_iZTZinv  crypto.CipherMatrix
	ScaledZTZ      crypto.CipherMatrix
	b              crypto.CipherVector
	ScaledXTZCache crypto.PlainMatrix
	invStd         []float64
	rho            float64
	allN           int
	C              int
	T              int
}

//keep XTZ seperate when multiplying
func NewADMM_Wood(params *ADMMParams, block, fold int, calcGTicketsChannel chan int) *ADMM_Wood {
	rho := params.rho
	N := params.allN
	cps := params.cps
	mpcObj := params.mpcObj
	pid := mpcObj.GetPid()
	P := mpcObj.GetNParty() - 1
	C := params.C
	T := params.T
	var invStdPlain crypto.PlainVector
	var ScaledSX_iTZ_iCache crypto.PlainMatrix
	var AinvSX_iTZ_iCache crypto.PlainMatrix
	var ScaledAinv *mat.Dense
	var Z_iTX_iSAinv *mat.Dense
	var ScaledSX_iTZ_i *mat.Dense
	if pid > 0 {
		invStdPlain, _ = crypto.EncodeFloatVector(cps, params.invStd)
		ScaledAinv = mat.NewDense(T, T, nil)
		SATAS := params.ATA
		inner := mat.DenseCopyOf(SATAS)
		for i := 0; i < T; i++ {
			val := inner.At(i, i)
			inner.Set(i, i, val+rho)
		}
		inner.Scale(1/(math.Sqrt(float64(N))*rho), inner)
		err := ScaledAinv.Inverse(inner)
		if err != nil {
			log.Fatalf("A is not invertible: %v", err)
		}
		ScaledSX_iTZ_i = params.ScaledX_iTZ_i
		Z_iTX_iSAinv = mat.NewDense(C, T, nil)
		Z_iTX_iSAinv.Mul(ScaledSX_iTZ_i.T(), ScaledAinv)
		AinvSX_iTZ_iCache = crypto.EncodeDense(cps, mat.DenseCopyOf(Z_iTX_iSAinv.T())) // want to keep a larger scaled version
		ScaledSX_iTZ_iCache = crypto.EncodeDense(cps, ScaledSX_iTZ_i)
	}
	ScaledSXTZAll := make(crypto.CipherMatrix, len(params.ScaledXTZAll))
	if pid > 0 {
		for i := 0; i < len(params.ScaledXTZAll); i++ {
			ScaledSXTZAll[i] = crypto.CPMult(cps, params.ScaledXTZAll[i], invStdPlain)
		}
		ScaledSXTZAll = params.mpcObjs.GetNetworks().BootstrapMatAll(cps, ScaledSXTZAll)
	}
	admm := &ADMM_Wood{
		general:             params.general,
		ScaledAinv:          ScaledAinv,
		mpcObj:              params.mpcObj,
		mpcObjs:             params.mpcObjs,
		cps:                 params.cps,
		b:                   params.b,
		C:                   params.C,
		T:                   T,
		block:               block,
		fold:                fold,
		P:                   P,
		N:                   params.allN,
		rho:                 params.rho,
		AinvSX_iTZ_iCache:   AinvSX_iTZ_iCache,
		Z_iTZ_iZTZinv:       params.Z_iTZ_iZTZinv,
		ScaledSXTZAll:       ScaledSXTZAll,
		ScaledSX_iTZ_iCache: ScaledSX_iTZ_iCache,
	}
	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Caching done except for Calculate G")
	start := time.Now()

	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Waiting for ticket")
	var ticket int
	if pid == mpcObj.GetHubPid() {
		ticket = <-calcGTicketsChannel // Wait for ticket
		for other := 0; other < mpcObj.GetNParty(); other++ {
			if other != pid {
				mpcObj.Network.SendInt(ticket, other)
			}
		}
	} else {
		ticket = mpcObj.Network.ReceiveInt(mpcObj.GetHubPid())
	}
	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Beginning to calculate G")
	admm.calculate_G(params.ScaledZTZ, ScaledSX_iTZ_i, Z_iTX_iSAinv, block, fold)

	if pid == mpcObj.GetHubPid() {
		calcGTicketsChannel <- ticket // Return ticket
	}

	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Preprocessing time: ", time.Now().Sub(start).String())
	return admm
}

func (admm *ADMM_Wood) step(alpha float64, scaledB crypto.CipherVector) {
	cps := admm.cps
	mpcObj := admm.mpcObj
	pid := mpcObj.GetPid()
	var innerVec crypto.CipherVector
	if pid > 0 {
		ZminusNu := crypto.CSub(cps, admm.Z, admm.Nu)
		innerSum := crypto.CAdd(cps, scaledB, ZminusNu)
		innerSum = crypto.CMultConst(cps, innerSum, math.Sqrt(admm.rho), false)
		innerSum = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, innerSum)
		innerVec = admm.multAinvVec(innerSum)
		innerVec = crypto.CMultConst(cps, innerVec, math.Sqrt(admm.rho), false)
		innerVec = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, innerVec)
	}
	admm.X = admm.woodbury(innerVec)
	if pid > 0 {
		admm.X = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, admm.X)
		XBar := admm.calculateMean(admm.X)
		admm.XBarminusZ = crypto.CSub(cps, XBar, admm.Z) //for error peek

		NuBar := admm.calculateMean(admm.Nu)
		num := crypto.CAdd(cps, XBar, NuBar)
		p := admm.mpcObj.GetNParty() - 1
		scale := math.Sqrt(admm.rho) / math.Sqrt(alpha/float64(p)+admm.rho)

		num = crypto.CMultConst(cps, num, scale, false)
		admm.Z = crypto.CMultConst(cps, num, scale, false)
		admm.Z = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, admm.Z)
		XminusZ := crypto.CSub(cps, admm.X, admm.Z)
		admm.Nu = crypto.CAdd(cps, admm.Nu, XminusZ)
	}
}

func (admm *ADMM_Wood) Run(alpha float64, scale float64, initX crypto.CipherVector, num_iterations, block, fold int) crypto.CipherVector {
	cps := admm.cps
	if initX == nil {
		admm.X = CRands(cps, admm.T) //reset params
	} else {
		admm.X = crypto.CopyEncryptedVector(initX)
	}
	admm.Nu = CZeros(cps, admm.T)
	admm.Z = CZeros(cps, admm.T)

	scaledB := crypto.CMultConst(cps, admm.b, scale, false)
	scaledB = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, scaledB)
	start := time.Now()
	for i := 0; i < num_iterations; i++ {
		admm.step(alpha, scaledB)
		log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Lambda", alpha, "ITERATION: ", i, time.Since(start))
		start = time.Now()
	}
	return admm.Z
}

func (admm *ADMM_Wood) woodbury(x crypto.CipherVector) crypto.CipherVector {
	cps := admm.cps
	mpcObj := admm.mpcObj
	pid := mpcObj.GetPid()
	var Vx1, Vx2 crypto.CipherVector
	if pid > 0 {
		Vx1, Vx2 = admm.multV(x)
	}
	res1, res2 := admm.multGinvSS(Vx1, Vx2)

	var out crypto.CipherVector
	if pid > 0 {
		wood := admm.multAinvU(res1, res2)
		wood = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, wood)
		scaledOut := crypto.CSub(cps, x, wood)
		out = crypto.CMultConst(cps, scaledOut, 1/math.Sqrt(float64(admm.N)), true) //artifically scale out
	}
	return out
}

func (admm *ADMM_Wood) multGinvSS(x crypto.CipherVector, y crypto.CipherVector) (crypto.CipherVector, crypto.CipherVector) {
	cps := admm.cps
	mpcObj := admm.mpcObj
	pid := mpcObj.GetPid()
	input := make(crypto.CipherVector, 2)
	if pid > 0 {
		input[0] = x[0]
		input[1] = y[0]
	}

	out := CMultWithRMatBlockParallel(cps, mpcObj, input, admm.ScaledGinvSSAll, admm.C)

	var res1, res2 crypto.CipherVector
	if pid > 0 {
		res1 = crypto.CipherVector{out[pid-1][0]}
		res2 = crypto.CipherVector{out[pid-1][1]}
	}

	return res1, res2
}

func (admm *ADMM_Wood) multAinv(x crypto.CipherMatrix) crypto.CipherMatrix {
	cps := admm.cps
	if admm.ScaledAinvCache == nil {
		admm.ScaledAinvCache = gwas.MatMult4TransformB(cps, admm.ScaledAinv)
	}
	res := gwas.CPMatMult4V2CachedB(cps, x, 5, admm.ScaledAinvCache)
	res = admm.mpcObjs.GetNetworks().BootstrapMatAll(cps, res)
	for i := 0; i < len(res); i++ {
		res[i] = crypto.CMultConst(cps, res[i], 1/admm.rho, false)
	}
	return res
}
func (admm *ADMM_Wood) multAinvVec(x crypto.CipherVector) crypto.CipherVector {
	return admm.multAinv(crypto.CipherMatrix{x})[0]
}

//2C x 1 vector in and N x 1 vector out
func (admm *ADMM_Wood) multAinvU(x crypto.CipherVector, y crypto.CipherVector) crypto.CipherVector {
	cps := admm.cps
	input := crypto.CMultConst(cps, y, math.Sqrt(1/admm.rho), false) //remove factor of rho
	second := gwas.CPMatMult5Parallel(cps, admm.AinvSX_iTZ_iCache, crypto.CipherMatrix{input})[0]
	second = crypto.CMultConst(cps, second, math.Sqrt(1/admm.rho), false)
	first := admm.mulXTZCipher(x)
	first = admm.mpcObjs.GetNetworks().BootstrapVecAll(cps, first)
	firstRes := admm.multAinvVec(first)
	res := crypto.CAdd(cps, firstRes, second)
	return res
}

//returns two Cx1 vectors seems to be very accurate
func (admm *ADMM_Wood) multV(x crypto.CipherVector) (crypto.CipherVector, crypto.CipherVector) {
	cps := admm.cps
	ScaledZ_iTX_i := gwas.CPMatMult1Parallel(cps, admm.ScaledSX_iTZ_iCache, crypto.CipherMatrix{x})[0]
	ScaledZTX := admm.mulZTXCipher(x)                                                             // C by 1
	ScaledL := gwas.CMatMult5Parallel(cps, admm.Z_iTZ_iZTZinv, crypto.CipherMatrix{ScaledZTX})[0] // need to scale
	ScaledL = crypto.CMultConst(cps, ScaledL, 1/math.Sqrt(float64(admm.N)), false)                //Z_iTZ_iZTZinv is scaled now	ScaledL = crypto.CMultConst(cps, ScaledL, 1/math.Sqrt(float64(admm.N)), false)      //Z_iTZ_iZTZinv is scaled now
	num := crypto.CSub(cps, ScaledZ_iTX_i, ScaledL)
	return num, ScaledZTX
}

func (admm *ADMM_Wood) mulZTXCipher(x crypto.CipherVector) crypto.CipherVector {
	cps := admm.cps
	out := gwas.CMatMult1Parallel(cps, admm.ScaledSXTZAll, crypto.CipherMatrix{x})[0]
	return out
}

func (admm *ADMM_Wood) mulXTZCipher(x crypto.CipherVector) crypto.CipherVector {
	cps := admm.cps
	out := gwas.CMatMult5Parallel(cps, admm.ScaledSXTZAll, crypto.CipherMatrix{x})[0]
	return out
}

//Calculates the inner G function of the woodbury transformation
func (admm *ADMM_Wood) calculate_G(ZTZ crypto.CipherMatrix, ScaledSX_iTZ_i, Z_iTX_iSAinv *mat.Dense, block, fold int) { //XTZ is a T x C matrix actually
	cps := admm.cps
	mpcObj := admm.mpcObj
	mpcObjs := admm.mpcObjs
	pid := mpcObj.GetPid()
	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Calculate G matrix")
	fname := "block_" + strconv.Itoa(block) + "/G_" + strconv.Itoa(pid) + "_" + strconv.Itoa(block) + "_" + strconv.Itoa(fold) + ".txt"
	var G crypto.CipherMatrix
	if admm.general.FileExistsForAll(mpcObj, admm.general.CacheFile(fname)) {
		log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Found G Matrix")
		if pid > 0 {
			G = gwas.LoadCacheFromFile(cps, admm.general.CacheFile(fname))
		}
	} else if pid > 0 {
		P := admm.multAinv(admm.ScaledSXTZAll) //correct P x \sqrt(N)
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated P")
		P = admm.mpcObjs.GetNetworks().BootstrapMatAll(cps, P)
		Y := make([]crypto.CipherVector, admm.C) // C by C
		for i := 0; i < len(P); i++ {
			Y[i] = admm.mulZTXCipher(P[i])
		}
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated Y")

		Y = admm.mpcObjs.GetNetworks().BootstrapMatAll(cps, Y)
		var AinvSX_iTZ_iEncr crypto.CipherMatrix
		var AinvSX_iTZ_i *mat.Dense
		AinvSX_iTZ_i = mat.DenseCopyOf(Z_iTX_iSAinv.T())          // accurate
		AinvSX_iTZ_iEncr = crypto.EncryptDense(cps, AinvSX_iTZ_i) // mul by sqrtN
		for i := 0; i < len(AinvSX_iTZ_iEncr); i++ {
			AinvSX_iTZ_iEncr[i] = crypto.CMultConst(cps, AinvSX_iTZ_iEncr[i], math.Sqrt(1/admm.rho), false) //remove rho factor
		}
		E := make([]crypto.CipherVector, admm.C) //C by C
		for i := 0; i < len(AinvSX_iTZ_iEncr); i++ {
			E[i] = admm.mulZTXCipher(AinvSX_iTZ_iEncr[i])
			E[i] = crypto.CMultConst(cps, E[i], math.Sqrt(1/admm.rho), false)
		}
		E = admm.mpcObjs.GetNetworks().BootstrapMatAll(cps, E)
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated E")
		ScaledZ_iTX_iSAinvSX_iTZ_i := mat.NewDense(admm.C, admm.C, nil)
		var num2 crypto.CipherMatrix
		ScaledZ_iTX_iSAinvSX_iTZ_i.Mul(ScaledSX_iTZ_i.T(), AinvSX_iTZ_i)                       //accurate
		ScaledZ_iTX_iSAinvSX_iTZ_i.Scale(1/admm.rho, ScaledZ_iTX_iSAinvSX_iTZ_i)               // remove factor rho
		ScaledZ_iTX_iSAinvSX_iTZ_iEncr := crypto.EncryptDense(cps, ScaledZ_iTX_iSAinvSX_iTZ_i) // times sqrtN
		num2 = gwas.CMatMult5Parallel(cps, admm.Z_iTZ_iZTZinv, E)
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated admm.Z_iTZ_iZTZinv, E")
		num2 = CMatMultConst(cps, num2, 1/math.Sqrt(float64(admm.N)))
		num2 = CMatSub(cps, ScaledZ_iTX_iSAinvSX_iTZ_iEncr, num2)

		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated num2")
		var num1 crypto.CipherMatrix
		num1 = gwas.CMatMult5Parallel(cps, admm.Z_iTZ_iZTZinv, Y) // CxC
		num1 = CMatMultConst(cps, num1, 1/math.Sqrt(float64(admm.N)))

		ET := gwas.CPMatMult1Parallel(cps, admm.ScaledSX_iTZ_iCache, P)
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated ET")

		num1 = CMatSub(cps, ET, num1)
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated num1")
		num1 = CMatSub(cps, num1, ZTZ)
		var denom2 crypto.CipherMatrix
		denom2 = CMatSub(cps, E, ZTZ)
		log.LLvl1(time.Now().Format(time.StampMilli), "E Again")
		G_block := []crypto.CipherMatrix{num1, num2, Y, denom2}
		G = make(crypto.CipherMatrix, admm.C*4)
		for i := 0; i < 4; i++ {
			block := G_block[i]
			for j := 0; j < admm.C; j++ {
				G[i*admm.C+j] = block[j]
			}
		}
		log.LLvl1(time.Now().Format(time.StampMilli), "Calculated G")
		G, _ := crypto.FlattenLevels(cps, G)
		for p := 1; p < mpcObj.GetNParty(); p++ {
			gwas.SaveMatrixToFile(cps, mpcObj, G, admm.C, p, admm.general.CacheFile(fname)) //need to figure out save matrix
		}
		log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "Calculating Ginv")
	}
	start := time.Now()
	ssAll := mpcObj.CMatToSSAll(cps, G, admm.C*4, 1, admm.C)
	for i := 0; i < len(ssAll); i++ {
		ssAll[i] = refactorMatrix(ssAll[i], admm.C)
	}
	GinvSS := mpcObjs.MatrixInverseSVD(ssAll)
	log.LLvl1(time.Now().Format(time.StampMilli), "GinvSS", time.Now().Sub(start).String())
	admm.ScaledGinvSSAll = GinvSS
	log.LLvl1(time.Now().Format(time.StampMilli), "Block", block, "Fold", fold, "ADMM is ready")

}
func (admm *ADMM_Wood) calculateMean(x crypto.CipherVector) crypto.CipherVector {
	network := admm.mpcObj.Network
	cps := admm.cps
	agg := network.AggregateCVec(cps, x)
	P := network.GetNParty() - 1
	return crypto.CMultConst(cps, agg, 1/float64(P), true)
}

//X is 4nxn matrix to 2nx2n
//n=C here
func refactorMatrix(X mpc_core.RMat, n int) mpc_core.RMat {
	res := make(mpc_core.RMat, 2*n)
	for i := 0; i < (2 * n); i++ {
		concat := make(mpc_core.RVec, 2*n)
		for j := 0; j < n; j++ {
			concat[j] = X[i][j]
			concat[j+n] = X[i+2*n][j]
		}
		res[i] = concat
	}
	return res
}
