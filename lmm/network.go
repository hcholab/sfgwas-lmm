package lmm

import (
	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/hhcho/sfgwas-lmm/gwas"
	"github.com/hhcho/sfgwas-lmm/mpc"
	"github.com/ldsec/lattigo/v2/ckks"
)

// Assumes X and Y are the same for all parties
func AllCDotBroadcast(cps *crypto.CryptoParams, mpcObj *mpc.MPC, X crypto.CipherVector, Y crypto.CipherVector) *ckks.Ciphertext {
	var res *ckks.Ciphertext
	if mpcObj.GetPid() == mpcObj.GetHubPid() {
		res = CDot(cps, X, Y)
	}
	res = mpcObj.Network.BroadcastCiphertext(cps, res, mpcObj.GetHubPid())
	return res
}

// Assumes X and Y are shares for all parties and aggregates at the end
func AllCDot(general *gwas.ProtocolInfoLMM, X crypto.CipherVector, Y crypto.CipherVector) *ckks.Ciphertext {
	mpcObj := general.GetMPC()
	cps := general.GetCPS()
	res := CDot(cps, X, Y)
	return mpcObj.Network.AggregateCText(cps, res)
}

type LazyMultMat func(x crypto.CipherMatrix) crypto.CipherMatrix

func AllCacheMul(cps *crypto.CryptoParams, mpcObj *mpc.MPC, lazyMult LazyMultMat, X crypto.CipherMatrix, outLen int) crypto.CipherMatrix {
	network := mpcObj.Network

	res := make([]crypto.CipherMatrix, network.GetNParty()-1) // because of pid = 0

	//get shares from everyone except for pid = 0
	pid := network.GetPid()
	for i := 1; i < network.GetNParty(); i++ {
		if pid == i {
			res[i-1] = X
		} else if i > pid {
			//receive first and then send
			res[i-1] = network.ReceiveCipherMatrix(cps, len(X), len(X[0]), i) //don't know if this is how to accurately find len of ciphervec
			network.SendCipherMatrix(X, i)
		} else {
			//send and then receive
			network.SendCipherMatrix(X, i)
			res[i-1] = network.ReceiveCipherMatrix(cps, len(X), len(X[0]), i)
		}
	}
	//mask and mult
	out := make(crypto.CipherMatrix, outLen)
	for i := 1; i < network.GetNParty(); i++ {
		multRes := lazyMult(res[i-1])
		if pid == i {
			out = network.AggregateCMat(cps, multRes)
		} else {
			network.AggregateCMat(cps, multRes)
		}
	}

	return out
}

func AllCacheMulVec(cps *crypto.CryptoParams, mpcObj *mpc.MPC, lazyMult LazyMult, X crypto.CipherVector, outLen int) crypto.CipherVector {
	lazyMultMatFn := func(x crypto.CipherMatrix) crypto.CipherMatrix {
		return crypto.CipherMatrix{lazyMult(x[0])}
	}
	return AllCacheMul(cps, mpcObj, lazyMultMatFn, crypto.CipherMatrix{X}, outLen)[0]
}
