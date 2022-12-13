package mpc

import (
	"github.com/aead/chacha20/chacha"
	"github.com/hhcho/frand"
	"github.com/hhcho/mpc-core"
	"go.dedis.ch/onet/v3/log"
	"time"
)

type Random struct {
	pid      int
	prgTable map[int]*frand.RNG
	curPRG   *frand.RNG
}

const (
	bufferSize int = 1024
	GlobalPRG  int = -1
)

func sortInt(a, b int) (int, int) {
	if a < b {
		return a, b
	}
	return b, a
}

func InitializePRG(pid int, NumParties int) *Random {
	/* TODO:
	 * Currently samples shared secrets from
	 * a deterministic stream. Need a key exchange
	 * protocol in practice.
	 */
	prgTable := make(map[int]*frand.RNG)

	// Globally shared PRG
	// TODO: temporary, insecure way of generating a shared seed
	seed := make([]byte, chacha.KeySize)
	prgTable[-1] = frand.NewCustom(seed, bufferSize, 20)

	// Pairwise-shared PRG
	for i := 0; i < NumParties; i++ {
		if i == pid {
			continue
		}

		// TODO: temporary, insecure way of generating a shared seed
		a, b := sortInt(pid, i)
		seed[0] = byte(a)
		seed[1] = byte(b)

		prgTable[i] = frand.NewCustom(seed, bufferSize, 20)
	}

	// Local PRG
	log.LLvl1(time.Now(), "Deterministic local seed for debugging")
	//frand.Read(seed)
	prgTable[pid] = frand.NewCustom(seed, bufferSize, 20)
	curPRG := prgTable[pid]
	return &Random{
		prgTable: prgTable,
		curPRG:   curPRG,
		pid:      pid,
	}
}

func (rand *Random) SwitchPRG(otherPid int) {
	rand.curPRG = rand.prgTable[otherPid]
}

func (rand *Random) RestorePRG() {
	rand.curPRG = rand.prgTable[rand.pid]
}

func (rand *Random) CurPRG() *frand.RNG {
	return rand.curPRG
}

func (rand *Random) ExportPRG() []byte {
	return rand.curPRG.Marshal()
}

func (rand *Random) ImportPRG(buf []byte, prgId int) {
	rand.prgTable[prgId] = frand.Unmarshal(buf, bufferSize)
}

func (rand *Random) RandRead(buf []byte) {
	rand.curPRG.Read(buf)
}

func (rand *Random) RandElem(rtype mpc_core.RElem) mpc_core.RElem {
	return rtype.Rand(rand.curPRG)
}

func (rand *Random) RandVec(rtype mpc_core.RElem, n int) mpc_core.RVec {
	out := make(mpc_core.RVec, n)
	for i := range out {
		out[i] = rtype.Rand(rand.curPRG)
	}
	return out
}

func (rand *Random) RandMat(rtype mpc_core.RElem, r int, c int) mpc_core.RMat {
	out := make(mpc_core.RMat, r)
	for i := range out {
		out[i] = rand.RandVec(rtype, c)
	}
	return out
}

// Sample n random numbers with bit-length nbits in rtype
func (rand *Random) RandVecBits(rtype mpc_core.RElem, n, nbits int) mpc_core.RVec {
	out := make(mpc_core.RVec, n)
	for i := range out {
		out[i] = rtype.RandBits(rand.curPRG, nbits)
	}
	return out
}

// Sample random numbers with bit-length nbits in rtype
func (rand *Random) RandMatBits(rtype mpc_core.RElem, nrows, ncols, nbits int) mpc_core.RMat {
	out := make(mpc_core.RMat, nrows)
	for i := range out {
		out[i] = rand.RandVecBits(rtype, ncols, nbits)
	}
	return out
}
