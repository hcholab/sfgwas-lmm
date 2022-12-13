package mpc

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"go.dedis.ch/onet/v3/log"

	"github.com/ldsec/lattigo/v2/ckks"
)

func (netObj ParallelNetworks) CollectiveInit(params *ckks.Parameters, prec uint) (cps *crypto.CryptoParams) {
	fmt.Println("CollectiveInit")

	dckksContext := dckks.NewContext(params)

	var kgen = ckks.NewKeyGenerator(params)

	var skShard *ckks.SecretKey
	if netObj[0].GetPid() == 0 {
		skShard = new(ckks.SecretKey)
		skShard.Value = dckksContext.RingQP.NewPoly()
	} else {
		skShard = kgen.GenSecretKey()

		//TODO
		log.LLvl1(time.Now(), "Dummy secret keys for debugging")
		skShard.Value.Zero()
		prng, err := utils.NewKeyedPRNG(nil)
		if err != nil {
			panic(err)
		}
		ternarySamplerMontgomery := ring.NewTernarySampler(prng, dckksContext.RingQP, 1.0/3.0, true)
		skShard.Value = ternarySamplerMontgomery.ReadNew()
		dckksContext.RingQP.NTT(skShard.Value, skShard.Value)
		log.LLvl1(time.Now(), "SK:", skShard.Value.Coeffs[0][0], skShard.Value.Coeffs[1][1], skShard.Value.Coeffs[2][2])
	}

	// TODO: globally shared key
	crpGen := make([]*ring.UniformSampler, len(netObj))
	for i := range crpGen {
		crpKey := make([]byte, 64)
		netObj[0].Rand.SwitchPRG(-1)
		netObj[0].Rand.RandRead(crpKey)
		netObj[0].Rand.RestorePRG()

		//TODO
		log.LLvl1(time.Now(), "crpKey check", crpKey[:5])

		prng, _ := utils.NewKeyedPRNG(crpKey)
		crpGen[i] = ring.NewUniformSampler(prng, dckksContext.RingQP)
	}

	//TODO
	p := crpGen[0].ReadNew()
	log.LLvl1(time.Now(), "crpGen check", p.Coeffs[0][0], p.Coeffs[1][1], p.Coeffs[2][2])

	fmt.Println("PubKeyGen")
	var pk = netObj[0].CollectivePubKeyGen(params, skShard, crpGen[0])

	//TODO
	log.LLvl1(time.Now(), "PubKey check")
	log.LLvl1(pk.Value[0].Coeffs[0][0], pk.Value[0].Coeffs[1][1], pk.Value[0].Coeffs[2][2])
	log.LLvl1(pk.Value[1].Coeffs[0][0], pk.Value[1].Coeffs[1][1], pk.Value[1].Coeffs[2][2])

	fmt.Println("RelinKeyGen")
	var rlk = netObj[0].CollectiveRelinKeyGen(params, skShard, crpGen[0])

	//TODO
	d := rlk.Keys[0].Value[0][0].Coeffs
	log.LLvl1(time.Now(), "RelinKeyGen check", d[0][0], d[1][1], d[2][2])

	nprocs := runtime.GOMAXPROCS(0)
	cps = crypto.NewCryptoParams(params, skShard, skShard, pk, rlk, prec, nprocs)

	fmt.Println("RotKeyGen")
	if netObj[0].GetPid() > 0 {
		rotKs := netObj.CollectiveRotKeyGen(params, skShard, crpGen, crypto.GenerateRotKeys(cps.GetSlots(), 20, true))
		// rotKs := netObj.CollectiveRotKeyGen(params, skShard, crpGen, crypto.GenerateRotKeys(1, 0, false))
		cps.RotKs = rotKs
		cps.SetEvaluators(cps.Params, rlk, cps.RotKs)
	}

	fmt.Println("Setup complete")
	return
}

func (netObj *Network) CollectivePubKeyGen(parameters *ckks.Parameters, skShard *ckks.SecretKey, crpGen *ring.UniformSampler) (pk *ckks.PublicKey) {
	sk := &skShard.SecretKey

	ckgProtocol := dckks.NewCKGProtocol(parameters)

	pkShare := ckgProtocol.AllocateShares()

	crp := crpGen.ReadNew()
	ckgProtocol.GenShare(sk, crp, pkShare)

	pkAgg := netObj.AggregatePubKeyShares(pkShare)

	hubPid := netObj.GetHubPid()
	if netObj.GetPid() == 0 {
		pkAgg.Poly = netObj.ReceivePoly(hubPid)
	} else if netObj.GetPid() == hubPid {
		netObj.SendPoly(pkAgg.Poly, 0)
	}

	pk = ckks.NewPublicKey(parameters)
	ckgProtocol.GenPublicKey(pkAgg, crp, &pk.PublicKey)
	return
}

func (netObj *Network) CollectiveDecryptMat(cps *crypto.CryptoParams, cm crypto.CipherMatrix, sourcePid int) (pm crypto.PlainMatrix) {
	pid := netObj.GetPid()
	if pid == 0 {
		return
	}

	var tmp crypto.CipherMatrix
	var nr, nc int

	if sourcePid > 0 {
		if pid == sourcePid {
			nr, nc = len(cm), len(cm[0])
			for p := 1; p < netObj.GetNParty(); p++ {
				if p != sourcePid {
					netObj.SendInt(nr, p)
					netObj.SendInt(nc, p)
				}
			}
		} else {
			nr = netObj.ReceiveInt(sourcePid)
			nc = netObj.ReceiveInt(sourcePid)
			cm = make(crypto.CipherMatrix, nr)
			cm[0] = make(crypto.CipherVector, nc)
		}

		tmp = netObj.BroadcastCMat(cps, cm, sourcePid, nr, nc)
	} else {
		nr = len(cm)
		nc = len(cm[0])
		tmp = crypto.CopyEncryptedMatrix(cm)
	}

	level := tmp[0][0].Level()
	scale := tmp[0][0].Scale()

	parameters := cps.Params
	skShard := cps.Sk.Value

	zeroPoly := parameters.NewPolyQP()

	zeroPk := new(ckks.PublicKey)
	zeroPk.Value = [2]*ring.Poly{zeroPoly, zeroPoly}

	pcksProtocol := dckks.NewPCKSProtocol(parameters, 6.36)

	decShare := make([][]dckks.PCKSShare, nr)
	for i := range decShare {
		decShare[i] = make([]dckks.PCKSShare, nc)
		for j := range decShare[i] {
			decShare[i][j] = pcksProtocol.AllocateShares(level)
			pcksProtocol.GenShare(skShard, zeroPk, tmp[i][j], decShare[i][j])
		}
	}

	decAgg := netObj.AggregateDecryptSharesMat(decShare, level)

	pm = make(crypto.PlainMatrix, nr)
	for i := range pm {
		pm[i] = make(crypto.PlainVector, nc)
		for j := range pm[i] {
			ciphertextSwitched := ckks.NewCiphertext(parameters, 1, level, scale)
			pcksProtocol.KeySwitch(decAgg[i][j], tmp[i][j], ciphertextSwitched)
			pm[i][j] = ciphertextSwitched.Plaintext()
		}
	}

	return
}

func (netObj *Network) CollectiveDecryptVec(cps *crypto.CryptoParams, cv crypto.CipherVector, sourcePid int) (pv crypto.PlainVector) {
	if netObj.GetPid() == 0 {
		return
	}
	return netObj.CollectiveDecryptMat(cps, crypto.CipherMatrix{cv}, sourcePid)[0]
}

func (netObj *Network) CollectiveDecrypt(cps *crypto.CryptoParams, ct *ckks.Ciphertext, sourcePid int) (pt *ckks.Plaintext) {
	var tmp *ckks.Ciphertext

	// sourcePid broadcasts ct to other parties for collective decryption
	if netObj.GetPid() == sourcePid {
		for p := 1; p < netObj.GetNParty(); p++ {
			if p != sourcePid {
				netObj.SendCiphertext(ct, p)
			}
		}
		tmp = ct
	} else if netObj.GetPid() > 0 {
		tmp = netObj.ReceiveCiphertext(cps, sourcePid)
	} else { // pid == 0
		return
	}

	parameters := cps.Params
	skShard := cps.Sk.Value

	zeroPoly := parameters.NewPolyQP()

	zeroPk := new(ckks.PublicKey)
	zeroPk.Value = [2]*ring.Poly{zeroPoly, zeroPoly}

	pcksProtocol := dckks.NewPCKSProtocol(parameters, 6.36)

	decShare := pcksProtocol.AllocateShares(tmp.Level())
	pcksProtocol.GenShare(skShard, zeroPk, tmp, decShare)
	decAgg := netObj.AggregateDecryptShares(&decShare, tmp.Level())

	ciphertextSwitched := ckks.NewCiphertext(parameters, 1, tmp.Level(), tmp.Scale())
	pcksProtocol.KeySwitch(*decAgg, tmp, ciphertextSwitched)

	pt = ciphertextSwitched.Plaintext()

	return
}

func (netObj *Network) CollectiveBootstrap(cps *crypto.CryptoParams, ct *ckks.Ciphertext, sourcePid int) {
	// sourcePid broadcasts ct to other parties for collective decryption
	if netObj.GetPid() == 0 {
		return
	}

	// if sourcePid <= 0, assume cm is already shared across parties
	if sourcePid > 0 {
		if netObj.GetPid() == sourcePid {
			for p := 1; p < netObj.GetNParty(); p++ {
				if p != sourcePid {
					netObj.SendCiphertext(ct, p)
				}
			}
		} else {
			ct = netObj.ReceiveCiphertext(cps, sourcePid)
		}
	}

	parameters := cps.Params
	skShard := cps.Sk.Value
	crpGen := netObj.GetCRPGen()
	levelStart := ct.Level()

	refProtocol := dckks.NewRefreshProtocol(parameters)
	refShare1, refShare2 := refProtocol.AllocateShares(levelStart)

	crp := crpGen.ReadNew()

	refProtocol.GenShares(skShard, levelStart, netObj.GetNParty()-1, ct, parameters.Scale(), crp, refShare1, refShare2)

	refAgg1 := netObj.AggregateRefreshShare(refShare1, levelStart)
	refAgg2 := netObj.AggregateRefreshShare(refShare2, parameters.MaxLevel())

	refProtocol.Decrypt(ct, refAgg1)           // Masked decryption
	refProtocol.Recode(ct, parameters.Scale()) // Masked re-encoding
	refProtocol.Recrypt(ct, crp, refAgg2)      // Masked re-encryption

	return
}

func (netObj *Network) CollectiveBootstrapVec(cps *crypto.CryptoParams, cv crypto.CipherVector, sourcePid int) crypto.CipherVector {
	return netObj.CollectiveBootstrapMat(cps, crypto.CipherMatrix{cv}, sourcePid)[0]
}

func (netObj *Network) CollectiveBootstrapMat(cps *crypto.CryptoParams, cm crypto.CipherMatrix, sourcePid int) crypto.CipherMatrix {
	if netObj.GetPid() == 0 {
		return cm
	}
	// start := time.Now()
	// log.LLvl1(time.Now().Format(time.StampMilli), "Start Collective Bootstrap")
	// if sourcePid <= 0, assume cm is already shared across parties
	if sourcePid > 0 {
		// sourcePid broadcasts ct to other parties for collective decryption
		if netObj.GetPid() == sourcePid {
			for p := 1; p < netObj.GetNParty(); p++ {
				if p != sourcePid {
					netObj.SendInt(len(cm), p)
					netObj.SendInt(len(cm[0]), p)
					netObj.SendCipherMatrix(cm, p)
				}
			}
		} else {
			ncols := netObj.ReceiveInt(sourcePid)
			nrows := netObj.ReceiveInt(sourcePid)
			cm = netObj.ReceiveCipherMatrix(cps, ncols, nrows, sourcePid)
		}
	}
	// log.LLvl1(time.Now().Format(time.StampMilli), "Network send matrices", time.Since(start))
	// start = time.Now()
	parameters := cps.Params.Copy()
	skShard := cps.Sk.Value.CopyNew()
	crpGen := netObj.GetCRPGen()

	cm, levelStart := crypto.FlattenLevels(cps, cm)
	// log.LLvl1(time.Now(), "Bootstrap: dimensions", len(cm), "x", len(cm[0]), "input level", levelStart)

	refProtocol := dckks.NewRefreshProtocol(parameters)
	// log.LLvl1(time.Now().Format(time.StampMilli), "Refresh protocol", time.Since(start))
	// startOver := time.Now()
	refSharesDecrypt := make([][]ring.Poly, len(cm))
	crps := make([][]ring.Poly, len(cm))
	refSharesRecrypt := make([][]ring.Poly, len(cm))

	for i := range cm {
		refSharesDecrypt[i] = make([]ring.Poly, len(cm[0]))
		crps[i] = make([]ring.Poly, len(cm[0]))
		refSharesRecrypt[i] = make([]ring.Poly, len(cm[0]))

		for j := range cm[i] {
			// start = time.Now()
			refShare1, refShare2 := refProtocol.AllocateShares(levelStart)
			// log.LLvl1(time.Now().Format(time.StampMilli), "Allocate", i, j, time.Since(start))
			refSharesDecrypt[i][j] = *refShare1
			refSharesRecrypt[i][j] = *refShare2
			// start = time.Now()
			crps[i][j] = *crpGen.ReadNew()
			// log.LLvl1(time.Now().Format(time.StampMilli), "crpGen ReadNew", i, j, time.Since(start))
			// start = time.Now()
			refProtocol.GenShares(skShard, levelStart, netObj.GetNParty()-1, cm[i][j], parameters.Scale(),
				&(crps[i][j]), &(refSharesDecrypt[i][j]), &(refSharesRecrypt[i][j]))
			// log.LLvl1(time.Now().Format(time.StampMilli), "GenShares", i, j, time.Since(start))
		}
	}
	// log.LLvl1(time.Now().Format(time.StampMilli), "Generate Shares", time.Since(startOver))
	// start = time.Now()
	refAgg1 := netObj.AggregateRefreshShareMat(refSharesDecrypt, levelStart)
	refAgg2 := netObj.AggregateRefreshShareMat(refSharesRecrypt, parameters.MaxLevel())
	// log.LLvl1(time.Now().Format(time.StampMilli), "Aggregate Shares", time.Since(start))
	// start = time.Now()
	for i := range cm {
		for j := range cm[i] {
			//no communication
			refProtocol.Decrypt(cm[i][j], &refAgg1[i][j])              // Masked decryption
			refProtocol.Recode(cm[i][j], parameters.Scale())           // Masked re-encoding
			refProtocol.Recrypt(cm[i][j], &crps[i][j], &refAgg2[i][j]) // Masked re-encryption

			// Fix discrepancy in number of moduli
			if len(cm[i][j].Value()[0].Coeffs) < len(cm[i][j].Value()[1].Coeffs) {
				log.LLvl1(time.Now(), "Potential issue in bootstrap")
				// poly := ring.NewPoly(len(cm[i][j].Value()[0].Coeffs[0]), len(cm[i][j].Value()[0].Coeffs))
				// for pi := range poly.Coeffs {
				// 	for pj := range poly.Coeffs[0] {
				// 		poly.Coeffs[pi][pj] = cm[i][j].Value()[1].Coeffs[pi][pj]
				// 	}
				// }
				// cm[i][j].Value()[1] = poly
			}
		}
	}
	// log.LLvl1(time.Now().Format(time.StampMilli), "Decrypt Final", time.Since(start))

	//log.LLvl1(time.Now(), "Bootstrap: output level", cm[0][0].Level())

	return cm

}

//BootstrapMatAll: collective bootstrap for all parties (except 0)
func (netObj *Network) BootstrapMatAll(cps *crypto.CryptoParams, cm crypto.CipherMatrix) crypto.CipherMatrix {

	tmp := make(crypto.CipherMatrix, len(cm))

	//TODO: optimize to run simultaneously
	for sourcePid := 1; sourcePid < netObj.GetNParty(); sourcePid++ {
		if netObj.GetPid() == sourcePid {
			cm = netObj.CollectiveBootstrapMat(cps, cm, sourcePid)
		} else {
			netObj.CollectiveBootstrapMat(cps, tmp, sourcePid)
		}
	}

	return cm
}

func (netObj *Network) BootstrapConcatVecAll(cps *crypto.CryptoParams, cv crypto.CipherVector) crypto.CipherVector {
	return netObj.BootstrapConcatMatAll(cps, crypto.CipherMatrix{cv})[0]
}

func (netObj *Network) BootstrapConcatMatAll(cps *crypto.CryptoParams, cm crypto.CipherMatrix) crypto.CipherMatrix {
	if netObj.GetPid() == 0 {
		return cm
	}
	pid := netObj.GetPid()
	var concat crypto.CipherMatrix
	cols := make([]int, netObj.GetNParty()-1)
	rows := make([]int, netObj.GetNParty()-1)
	if pid == netObj.GetHubPid() {
		total_cols := len(cm)
		tmp := make([]crypto.CipherMatrix, netObj.GetNParty()-1)
		for p := 1; p < netObj.GetNParty(); p++ {
			if p != pid {
				ncols := netObj.ReceiveInt(p)
				nrows := netObj.ReceiveInt(p)
				tmp[p-1] = netObj.ReceiveCipherMatrix(cps, ncols, nrows, p)
				total_cols += ncols
				cols[p-1] = ncols
				rows[p-1] = nrows
			} else {
				tmp[p-1] = cm
				cols[p-1] = len(cm)
				rows[p-1] = len(cm[0])
			}
		}
		check := rows[0]
		for i := 0; i < len(rows); i++ {
			if rows[i] != check {
				log.Fatalf("Not all CipherVectors the same Length")
			}
		}
		concat = make(crypto.CipherMatrix, total_cols)

		counter := 0
		for i := 0; i < netObj.GetNParty()-1; i++ {
			for j := 0; j < len(tmp[i]); j++ {
				concat[counter] = tmp[i][j]
				counter += 1
			}
		}
		fmt.Println("concat len, [0]len", len(concat), len(concat[0]))
	} else {
		netObj.SendInt(len(cm), netObj.GetHubPid())
		netObj.SendInt(len(cm[0]), netObj.GetHubPid())
		netObj.SendCipherMatrix(cm, netObj.GetHubPid())
	}

	concat = netObj.CollectiveBootstrapMat(cps, concat, netObj.GetHubPid())
	out := make(crypto.CipherMatrix, len(cm))
	startingIndex := 0
	for i := 0; i < pid; i++ {
		startingIndex += cols[i]
	}
	for j := 0; j < len(cm); j++ {
		out[j] = concat[j+startingIndex]
	}
	return out
}

func (netObj ParallelNetworks) BootstrapMatAll(cps *crypto.CryptoParams, cm crypto.CipherMatrix) crypto.CipherMatrix {
	var wg sync.WaitGroup
	numThreads := len(netObj)
	rounds := ((netObj[0].GetNParty() - 1) / numThreads) + 1
	for round := 0; round < rounds; round++ {
		for thread := 0; thread < numThreads; thread++ {
			sourcePid := numThreads*round + thread + 1
			if sourcePid < netObj[0].GetNParty() {
				wg.Add(1)
				// log.LLvl1(time.Now().Format(time.StampMilli), "BootstrapMatAll for ", sourcePid, ", thread:", thread, netObj[thread].GetPid())
				go func(cps *crypto.CryptoParams, thread, sourcePid int) {
					defer wg.Done()
					tmp := make(crypto.CipherMatrix, len(cm))
					if netObj[thread].GetPid() == sourcePid {
						cm = netObj[thread].CollectiveBootstrapMat(cps, cm, sourcePid)
					} else {
						netObj[thread].CollectiveBootstrapMat(cps, tmp, sourcePid)
					}
					// log.LLvl1(time.Now().Format(time.StampMilli), "Done BootstrapMatAll for ", sourcePid, ", thread:", thread, netObj[thread].GetPid())
				}(cps.CopyNoRotKeys(), thread, sourcePid)
			}
		}
		wg.Wait()
	}
	return cm
}

func (netObj *Network) DummyBootstrapVecAll(cps *crypto.CryptoParams, cv crypto.CipherVector) crypto.CipherVector {
	tmp := make(crypto.CipherVector, len(cv))

	for sourcePid := 1; sourcePid < netObj.GetNParty(); sourcePid++ {
		if netObj.GetPid() == sourcePid {
			pv := netObj.CollectiveDecryptVec(cps, cv, sourcePid)
			cv, _ = crypto.EncryptFloatVector(cps, crypto.DecodeFloatVector(cps, pv))
		} else {
			netObj.CollectiveDecryptVec(cps, tmp, sourcePid)
		}
	}

	return cv
}
func (netObj ParallelNetworks) BootstrapVecAll(cps *crypto.CryptoParams, cv crypto.CipherVector) crypto.CipherVector {
	cv = netObj.BootstrapMatAll(cps, crypto.CipherMatrix{cv})[0]
	return cv
}

func (netObj *Network) BootstrapVecAll(cps *crypto.CryptoParams, cv crypto.CipherVector) crypto.CipherVector {
	tmp := make(crypto.CipherVector, len(cv))

	for sourcePid := 1; sourcePid < netObj.GetNParty(); sourcePid++ {
		if netObj.GetPid() == sourcePid {
			cv = netObj.CollectiveBootstrapVec(cps, cv, sourcePid)
		} else {
			netObj.CollectiveBootstrapVec(cps, tmp, sourcePid)
		}
	}

	return cv
}

func (netObj ParallelNetworks) CollectiveRotKeyGen(parameters *ckks.Parameters, skShard *ckks.SecretKey,
	crpGen []*ring.UniformSampler, rotTypes []crypto.RotationType) (rotKeys *ckks.RotationKeySet) {

	slots := parameters.Slots()

	sk := &skShard.SecretKey

	shiftMap := make(map[int]bool)
	for _, rotType := range rotTypes {

		var shift int
		if rotType.Side == crypto.SideRight {
			shift = slots - rotType.Value
		} else {
			shift = rotType.Value
		}

		shiftMap[shift] = true
	}

	gElems := make([]uint64, len(shiftMap))
	i := 0
	for k := range shiftMap {
		gElems[i] = parameters.GaloisElementForColumnRotationBy(k)
		i++
	}

	// Need to sortInt otherwise different parties might have different ordering
	sort.Slice(gElems, func(i, j int) bool { return gElems[i] < gElems[j] })

	rotKeys = ckks.NewRotationKeySet(parameters, gElems)
	//
	//for ind, galEl := range gElems {
	//	rtgProtocol := dckks.NewRotKGProtocol(parameters)
	//	rtgShare := rtgProtocol.AllocateShares()
	//
	//	rtgCrp := make([]*ring.Poly, parameters.Beta())
	//	for i := 0; i < parameters.Beta(); i++ {
	//		rtgCrp[i] = crpGen[0].ReadNew()
	//	}
	//
	//	rtgProtocol.GenShare(sk, galEl, rtgCrp, rtgShare)
	//
	//	rtgAgg := netObj[0].AggregateRotKeyShare(rtgShare)
	//
	//	rtgProtocol.GenRotationKey(rtgAgg, rtgCrp, rotKeys.Keys[galEl])
	//	fmt.Println("Generate RotKey ", ind+1, "/", len(gElems), ", Galois element", galEl)
	//}

	/* Parallel version */
	nproc := len(netObj)
	jobChannels := make([]chan uint64, nproc)
	for i := range jobChannels {
		jobChannels[i] = make(chan uint64, 32)
	}

	// Dispatcher
	go func() {
		for ind, galEl := range gElems {
			jobChannels[ind%nproc] <- galEl
			fmt.Println("Generate RotKey ", ind+1, "/", len(gElems), ", Galois element", galEl)
		}
		for _, c := range jobChannels {
			close(c)
		}
	}()

	// Workers
	var wg sync.WaitGroup
	for thread := 0; thread < nproc; thread++ {
		wg.Add(1)
		go func(thread int, net *Network, crpGen *ring.UniformSampler) {
			defer wg.Done()
			for galEl := range jobChannels[thread] {
				rtgProtocol := dckks.NewRotKGProtocol(parameters)
				rtgShare := rtgProtocol.AllocateShares()

				rtgCrp := make([]*ring.Poly, parameters.Beta())
				for i := 0; i < parameters.Beta(); i++ {
					rtgCrp[i] = crpGen.ReadNew()
				}

				rtgProtocol.GenShare(sk, galEl, rtgCrp, rtgShare)

				rtgAgg := net.AggregateRotKeyShare(rtgShare)

				rtgProtocol.GenRotationKey(rtgAgg, rtgCrp, rotKeys.Keys[galEl])
			}
		}(thread, netObj[thread], crpGen[thread])
	}
	wg.Wait()

	return
}

func (netObj *Network) CollectiveRelinKeyGen(params *ckks.Parameters, skShard *ckks.SecretKey, crpGen *ring.UniformSampler) (evk *ckks.RelinearizationKey) {
	sk := &skShard.SecretKey

	prot := dckks.NewRKGProtocol(params)
	ephSk, share1, share2 := prot.AllocateShares()

	crp := make([]*ring.Poly, params.Beta())
	for i := 0; i < params.Beta(); i++ {
		crp[i] = crpGen.ReadNew()
	}

	evk = ckks.NewRelinearizationKey(params)

	if netObj.GetPid() > 0 {
		prot.GenShareRoundOne(sk, crp, ephSk, share1)
		outRound1 := netObj.AggregateRelinKeyShare(share1, true)

		prot.GenShareRoundTwo(ephSk, sk, outRound1, crp, share2)
		outRound2 := netObj.AggregateRelinKeyShare(share2, true)

		prot.GenRelinearizationKey(outRound1, outRound2, &evk.RelinearizationKey)
	}

	return
}

func (netObj *Network) BroadcastCMat(cps *crypto.CryptoParams, cm crypto.CipherMatrix, sourcePid int, numCtxRow, numCtxCol int) crypto.CipherMatrix {
	if netObj.GetPid() == sourcePid {
		if len(cm) != numCtxRow || len(cm[0]) != numCtxCol {
			panic("BroadcastCVec: dimensions of cm do not match numCtxRow or numCtxCol")
		}

		for p := 1; p < netObj.GetNParty(); p++ {
			if p != sourcePid {
				netObj.SendCipherMatrix(cm, p)
			}
		}
		cm = crypto.CopyEncryptedMatrix(cm)
	} else if netObj.GetPid() > 0 {
		cm = netObj.ReceiveCipherMatrix(cps, numCtxRow, numCtxCol, sourcePid)
	}
	return cm

}
func (netObj *Network) BroadcastCVec(cps *crypto.CryptoParams, cv crypto.CipherVector, sourcePid int, numCtx int) crypto.CipherVector {
	if netObj.GetPid() == sourcePid {
		if len(cv) != numCtx {
			panic("BroadcastCVec: len(cv) does not match numCtx")
		}

		for p := 1; p < netObj.GetNParty(); p++ {
			if p != sourcePid {
				netObj.SendCipherVector(cv, p)
			}
		}
		cv = crypto.CopyEncryptedVector(cv)
	} else if netObj.GetPid() > 0 {
		cv = netObj.ReceiveCipherVector(cps, numCtx, sourcePid)
	}
	return cv
}

func (netObj *Network) BroadcastCVecConcat(cps *crypto.CryptoParams, cv crypto.CipherVector, numCtx int) crypto.CipherMatrix {
	cm := make(crypto.CipherMatrix, netObj.GetNParty()-1)
	pid := netObj.GetPid()
	if pid == netObj.GetHubPid() {
		for p := 1; p < netObj.GetNParty(); p++ {
			if p == pid {
				cm[p-1] = cv
			} else {
				cm[p-1] = netObj.ReceiveCipherVector(cps, numCtx, p)
			}
		}
		for p := 1; p < netObj.GetNParty(); p++ {
			if p != pid {
				netObj.SendCipherMatrix(cm, p)
			}
		}
	} else if pid > 0 {
		netObj.SendCipherVector(cv, netObj.GetHubPid())
		cm = netObj.ReceiveCipherMatrix(cps, len(cm), numCtx, netObj.GetHubPid())
	} else {
		return crypto.CZeroMat(cps, numCtx, len(cm))
	}
	return cm
}

func (netObj *Network) BroadcastCiphertext(cps *crypto.CryptoParams, ct *ckks.Ciphertext, sourcePid int) *ckks.Ciphertext {
	if netObj.GetPid() == sourcePid {
		for p := 1; p < netObj.GetNParty(); p++ {
			if p != sourcePid {
				netObj.SendCiphertext(ct, p)
			}
		}
		ct = ct.CopyNew().Ciphertext()
	} else if netObj.GetPid() > 0 {
		ct = netObj.ReceiveCiphertext(cps, sourcePid)
	}
	return ct
}
