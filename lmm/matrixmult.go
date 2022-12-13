package lmm

import (
	"math"

	"github.com/hhcho/sfgwas-lmm/mpc"

	"github.com/ldsec/lattigo/v2/ckks"

	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/hhcho/sfgwas-lmm/gwas"
)

func (reg *REGENIE) XtildeMulStream(cps *crypto.CryptoParams, mpcObj *mpc.MPC, x crypto.CipherMatrix, fold int, block int, kminus bool) crypto.CipherMatrix {
	invstd := reg.invStdEncrBlock[block]
	scaled := make(crypto.CipherMatrix, len(x))
	for i := 0; i < len(x); i++ {
		scaled[i] = crypto.CMult(cps, x[i], invstd)
	}
	scaled = mpcObj.Network.BootstrapMatAll(cps, scaled)
	XTZMul := gwas.CMatMult1Parallel(cps, reg.ScaledXTZ[block], scaled)
	ZTZinvZTXMul := gwas.CMatMult5(cps, reg.ScaledZTZinvTwice, XTZMul) // recent change to Twice
	ZTZinvZTXMul = mpcObj.Network.BootstrapMatAll(cps, ZTZinvZTXMul)
	firstCorr := reg.MulZCache(cps, ZTZinvZTXMul, fold, kminus)
	firstCorr = mpcObj.Network.BootstrapMatAll(cps, firstCorr)
	for i := 0; i < len(firstCorr); i++ {
		firstCorr[i] = crypto.CMultConst(cps, firstCorr[i], 1.0/math.Sqrt(float64(reg.AllN)), false)
	}
	firstMult, _ := reg.MulXStream(cps, scaled, fold, block, kminus, false)
	firstRes := CMatSub(cps, firstMult, firstCorr)
	firstRes = mpcObj.Network.BootstrapMatAll(cps, firstRes)

	return firstRes
}
func (reg *REGENIE) XtildeMulVecStream(cps *crypto.CryptoParams, mpcObj *mpc.MPC, x crypto.CipherVector, fold int, block int, kminus bool) crypto.CipherVector {
	return reg.XtildeMulStream(cps, mpcObj, crypto.CipherMatrix{x}, fold, block, kminus)[0]
}

//xX where X is defined by a fold and a block
func (reg *REGENIE) MulXTStreamKminus(cps *crypto.CryptoParams, x HorCipherMatrix, fold int, block int, computeSquaredSum bool) (crypto.CipherMatrix, []float64) {
	geno := reg.general.GetGeno()
	var res crypto.CipherMatrix
	var sqSum []float64

	for i := 0; i < reg.K; i++ {
		if fold != i {
			share, sqSumShare := gwas.MatMult4StreamNProc(cps, x[i], geno[i][block], 5, computeSquaredSum, reg.NProc)
			if res == nil {
				res = share
				sqSum = sqSumShare
			} else {
				res = CMatAdd(cps, res, share)
				if sqSumShare != nil {
					for j := range sqSum {
						sqSum[j] += sqSumShare[j]
					}
				}
			}
		}
	}
	return res, sqSum
}

func (reg *REGENIE) MulXTStreamFold(cps *crypto.CryptoParams, x crypto.CipherMatrix, fold int, block int, computeSquaredSum bool) (crypto.CipherMatrix, []float64) {
	geno := reg.general.GetGeno()
	res, sqSum := gwas.MatMult4StreamNProc(cps, x, geno[fold][block], 5, computeSquaredSum, reg.NProc)
	return res, sqSum
}

// //xXT where X is defined by a fold and a block
func (reg *REGENIE) MulXStream(cps *crypto.CryptoParams, x crypto.CipherMatrix, fold int, block int, kminus bool, computeSquaredSum bool) (crypto.CipherMatrix, []float64) {
	genoT := reg.general.GetGenoT()
	var res crypto.CipherMatrix
	var sqSum []float64

	if kminus {
		//need to split this into K-1 sections
		for i := 0; i < reg.K; i++ {
			if fold != i {
				share, sqSumShare := gwas.MatMult4StreamNProc(cps, x, genoT[i][block], 5, computeSquaredSum, reg.NProc)
				if res == nil {
					res = share
					sqSum = sqSumShare
				} else {
					res = CMatAdd(cps, res, share)
					if sqSumShare != nil {
						for j := range sqSum {
							sqSum[j] += sqSumShare[j]
						}
					}
				}
			}
		}
	} else {
		res, sqSum = gwas.MatMult4StreamNProc(cps, x, genoT[fold][block], 5, computeSquaredSum, reg.NProc)
	}
	return res, sqSum
}

func (reg *REGENIE) MulZCache(cps *crypto.CryptoParams, x crypto.CipherMatrix, fold int, kminus bool) crypto.CipherMatrix {
	var res crypto.CipherMatrix
	if kminus {
		res = gwas.CPMatMult5Parallel(cps, reg.ZkminusCache[fold], x)
	} else {
		res = gwas.CPMatMult5Parallel(cps, reg.ZCache[fold], x)
	}
	return res
}

func (reg *REGENIE) MulZTCache(cps *crypto.CryptoParams, x crypto.CipherMatrix, fold int) crypto.CipherMatrix {
	return gwas.CPMatMult1Parallel(cps, reg.ZCache[fold], x)
}

//n is the size of Y and X ciphervectors
func (reg *REGENIE) MultLazyCMatTParallel(cps *crypto.CryptoParams, mpcObjs *mpc.ParallelMPC, X crypto.CipherMatrix, Y crypto.CipherMatrix, mean, stdinv crypto.CipherVector, n int) crypto.CipherMatrix {
	out := gwas.CMatMult1Parallel(cps, X, Y)
	out = mpcObjs.GetNetworks()[0].AggregateCMat(cps, out)
	out = mpcObjs.GetNetworks()[0].CollectiveBootstrapMat(cps, out, -1)
	for i := range out {
		rowSum := crypto.InnerSumAll(cps, Y[i])
		rowSum = mpcObjs.GetNetworks()[0].AggregateCText(cps, rowSum)
		Q1m := crypto.CMultScalar(cps, mean, rowSum)
		cps.WithEvaluator(func(eval ckks.Evaluator) error {
			for j := range out[i] {
				eval.Sub(out[i][j], Q1m[j], out[i][j])
			}
			return nil
		})
	}
	// Compute ((Q * X^T) - ((Q * 1) * m^T)) * S
	for i := range out {
		out[i] = crypto.CMult(cps, out[i], stdinv)
	}
	out = mpcObjs.GetNetworks().BootstrapMatAll(cps, out)
	return out
}

func (reg *REGENIE) MultLazyCMatParallel(cps *crypto.CryptoParams, mpcObjs *mpc.ParallelMPC, X crypto.CipherMatrix, Y crypto.CipherMatrix, mean, stdinv crypto.CipherVector, n int) crypto.CipherMatrix {
	slots := cps.GetSlots()
	vecLen := int((n-1)/slots) + 1
	totalVecLen := vecLen * slots
	maskClear := make([]float64, totalVecLen)
	for i := 0; i < totalVecLen; i++ {
		if i < n {
			maskClear[i] = 1
		} else {
			maskClear[i] = 0
		}
	}
	mask, _ := crypto.EncodeFloatVector(cps, maskClear)
	SY := make(crypto.CipherMatrix, len(Y))
	for i := range Y {
		SY[i] = crypto.CMult(cps, Y[i], stdinv)
	}
	SY = mpcObjs.GetNetworks().BootstrapMatAll(cps, SY)

	dupCts := make(crypto.CipherMatrix, len(Y))
	for i := range Y {
		meanCenter := crypto.CMult(cps, mean, SY[i])
		innerSum := crypto.InnerSumAll(cps, meanCenter) // might need to change
		dupCt := make(crypto.CipherVector, vecLen)
		for j := range dupCt {
			dupCt[j] = innerSum
		}
		dupCt = crypto.CPMult(cps, dupCt, mask)
		dupCts[i] = dupCt //this is waht accrues errors so need to mask
	}

	XSY := gwas.CMatMult5Parallel(cps, X, SY)
	XSY = mpcObjs.GetNetworks().BootstrapMatAll(cps, XSY)

	res := make(crypto.CipherMatrix, len(XSY))
	for i := range Y {
		res[i] = crypto.CSub(cps, XSY[i], dupCts[i])
	}

	return res
}

func (reg *REGENIE) XtildeTMulStreamLocal(cps *crypto.CryptoParams, mpcObj *mpc.MPC, x crypto.CipherMatrix, fold, block int) crypto.CipherMatrix {
	invstd := reg.invStdEncrBlock[block]
	Z_iTMul := reg.MulZTCache(cps, x, fold) // ZTfirstRes
	Z_iTMul = mpcObj.Network.BootstrapMatAll(cps, Z_iTMul)
	ZTZinvZ_iTMul := gwas.CMatMult5Parallel(cps, reg.ScaledZTZinvTwice, Z_iTMul)
	ZTZinvZ_iTMul = mpcObj.Network.BootstrapMatAll(cps, ZTZinvZ_iTMul)
	secCorr := gwas.CMatMult5Parallel(cps, reg.ScaledXTZ[block], ZTZinvZ_iTMul)
	secCorr = mpcObj.Network.BootstrapMatAll(cps, secCorr)

	for i := 0; i < len(secCorr); i++ {
		secCorr[i] = crypto.CMultConst(cps, secCorr[i], 1.0/math.Sqrt(float64(reg.AllN)), false)
	}
	secMult, _ := reg.MulXTStreamFold(cps, x, fold, block, false)
	res := CMatSub(cps, secMult, secCorr)
	for i := 0; i < len(res); i++ {
		res[i] = crypto.CMult(cps, res[i], invstd)
	}
	res = mpcObj.Network.BootstrapMatAll(cps, res)
	return res
}

func (reg *REGENIE) XtildeTMulVecStreamLocal(cps *crypto.CryptoParams, mpcObj *mpc.MPC, x crypto.CipherVector, fold, block int) crypto.CipherVector {
	return reg.XtildeTMulStreamLocal(cps, mpcObj, crypto.CipherMatrix{x}, fold, block)[0]
}
