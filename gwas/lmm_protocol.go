package gwas

import "C"
import (
	"os"
	"path"
	"time"

	"fmt"

	"go.dedis.ch/onet/v3/log"

	mpc_core "github.com/hhcho/mpc-core"

	"github.com/ldsec/lattigo/v2/ckks"

	"github.com/hhcho/sfgwas-lmm/crypto"
	"github.com/hhcho/sfgwas-lmm/mpc"
	"gonum.org/v1/gonum/mat"
)

type ProtocolInfoLMM struct {
	mpcObj mpc.ParallelMPC
	cps    *crypto.CryptoParams

	// Input files
	genoBlocks     [][]*GenoFileStream
	genoTBlocks    [][]*GenoFileStream
	genoBlockSizes []int
	genoFoldSizes  []int
	genoBlockToChr []int
	folds          int
	numChrs        int

	geno  *GenoFileStream
	genoT *GenoFileStream
	pheno *mat.Dense
	cov   *mat.Dense
	pos   []uint64

	gwasParams *GWASParams

	config *Config
}

func (g *ProtocolInfoLMM) FileExistsForAll(mpcObj *mpc.MPC, filename string) bool {
	flag := make([]uint64, 1)
	pid := mpcObj.GetPid()

	if pid > 0 {
		if _, err := os.Stat(filename); err == nil {
			flag[0] = 1
		}
	}

	flagSum := mpcObj.Network.AggregateIntVec(flag)
	if pid == mpcObj.GetHubPid() {
		mpcObj.Network.SendInt(int(flagSum[0]), 0)
	} else if pid == 0 {
		flagSum = make([]uint64, 1)
		flagSum[0] = uint64(mpcObj.Network.ReceiveInt(mpcObj.GetHubPid()))
	}
	return int(flagSum[0]) == (mpcObj.GetNParty() - 1)
}

func (g *ProtocolInfoLMM) OutFile(filename string) string {
	return path.Join(g.config.OutDir, filename)
}

func (g *ProtocolInfoLMM) OutExists(filename string) bool {
	fname := g.OutFile(filename)
	if _, err := os.Stat(fname); err == nil {
		return true
	}
	return false
}

func (g *ProtocolInfoLMM) CacheFile(filename string) string {
	return path.Join(g.config.CacheDir, filename)
}

func (g *ProtocolInfoLMM) CacheExists(filename string) bool {
	fname := g.CacheFile(filename)
	if _, err := os.Stat(fname); err == nil {
		return true
	}
	return false
}

func (g *ProtocolInfoLMM) Exists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}

func InitializeLMMProtocol(config *Config, pid int) (lmmProt *ProtocolInfoLMM) {
	log.LLvl1(time.Now(), "Init LMM Protocol")

	var chosen int
	switch config.CkksParams {
	case "PN12QP109":
		chosen = ckks.PN12QP109
	case "PN13QP218":
		chosen = ckks.PN13QP218
	case "PN14QP438":
		chosen = ckks.PN14QP438
	case "PN15QP880":
		chosen = ckks.PN15QP880
	case "PN16QP1761":
		chosen = ckks.PN16QP1761
	default:
		panic("Undefined value of CKKS params in config")
	}

	params := ckks.DefaultParams[chosen]
	prec := uint(config.MpcFieldSize)
	networks := mpc.ParallelNetworks(mpc.InitCommunication(config.Servers, pid, config.NumMainParties+1, config.MpcNumThreads))
	for thread := range networks {
		networks[thread].SetMHEParams(params)
	}

	var rtype mpc_core.RElem
	switch config.MpcFieldSize {
	case 256:
		rtype = mpc_core.LElem256Zero
	case 128:
		rtype = mpc_core.LElem128Zero
	default:
		panic("Unsupported value of MPC field size")
	}

	log.LLvl1(fmt.Sprintf("MPC parameters: bit length %d, data bits %d, frac bits %d",
		config.MpcFieldSize, config.MpcDataBits, config.MpcFracBits))
	mpcEnv := mpc.InitParallelMPCEnv(networks, rtype, config.MpcDataBits, config.MpcFracBits)
	for thread := range mpcEnv {
		mpcEnv[thread].SetHubPid(config.HubPartyId)
	}

	//TODO
	log.LLvl1(time.Now(), "Debugging output: PRGs initial state")
	for i := 0; i <= config.NumMainParties; i++ {
		if i != pid {
			mpcEnv[0].Network.Rand.SwitchPRG(i)
		}
		r := mpcEnv[0].Network.Rand.RandElem(mpcEnv[0].GetRType())
		if i != pid {
			mpcEnv[0].Network.Rand.RestorePRG()
		}
		log.LLvl1(pid, i, ":", r)
	}

	cps := networks.CollectiveInit(params, prec)

	cv, _ := crypto.EncryptFloatVector(cps, make([]float64, 1))
	d := cv[0].Value()[0].Coeffs
	log.LLvl1(time.Now(), "Enc check", d[0][0], d[1][1], d[2][2])

	folds := config.GenoNumFolds
	var pheno, cov *mat.Dense
	if pid > 0 {
		tab := '\t'
		pheno = LoadMatrixFromFile(config.PhenoFile, tab)
		cov = LoadMatrixFromFile(config.CovFile, tab)

	}

	gwasParams := InitGWASParams(config.NumInds, config.NumSnps, config.NumCovs, config.NumPCs, config.SnpDistThres)

	return &ProtocolInfoLMM{
		mpcObj:     mpcEnv, // One MPC object for each thread
		cps:        cps,
		folds:      folds,
		pheno:      pheno,
		cov:        cov,
		gwasParams: gwasParams,
		config:     config,
	}
}

func (g *ProtocolInfoLMM) SetGenoBlocks(geno [][]*GenoFileStream) {
	g.genoBlocks = geno
}
func (g *ProtocolInfoLMM) SetGenoTBlocks(genoT [][]*GenoFileStream) {
	g.genoTBlocks = genoT
}
func (g *ProtocolInfoLMM) GetCPS() *crypto.CryptoParams {
	return g.cps
}
func (g *ProtocolInfoLMM) GetMPC() *mpc.MPC {
	return g.mpcObj[0]
}
func (g *ProtocolInfoLMM) GetNetwork() *mpc.Network {
	return g.mpcObj[0].Network
}
func (g *ProtocolInfoLMM) GetParallelMPC() mpc.ParallelMPC {
	return g.mpcObj
}
func (g *ProtocolInfoLMM) GetParallelNetwork() mpc.ParallelNetworks {
	return g.mpcObj.GetNetworks()
}
func (g *ProtocolInfoLMM) GetGWASParams() *GWASParams {
	return g.gwasParams
}
func (g *ProtocolInfoLMM) SetGWASParams(x *GWASParams) {
	g.gwasParams = x
}
func (g *ProtocolInfoLMM) GetCov() *mat.Dense {
	return g.cov
}
func (g *ProtocolInfoLMM) GetGeno() [][]*GenoFileStream {
	return g.genoBlocks
}
func (g *ProtocolInfoLMM) GetGenoT() [][]*GenoFileStream {
	return g.genoTBlocks
}
func (g *ProtocolInfoLMM) GetConfig() *Config {
	return g.config
}
func (g *ProtocolInfoLMM) GetPheno() *mat.Dense {
	return g.pheno
}
func (g *ProtocolInfoLMM) GetGenoBlockSizes() []int {
	return g.genoBlockSizes
}
func (g *ProtocolInfoLMM) SetGenoBlockSizes(x []int) {
	g.genoBlockSizes = x
}
func (g *ProtocolInfoLMM) GetGenoFoldSizes() []int {
	return g.genoFoldSizes
}
func (g *ProtocolInfoLMM) SetGenoFoldSizes(x []int) {
	g.genoFoldSizes = x
}
func (g *ProtocolInfoLMM) GetGenoBlockToChr() []int {
	return g.genoBlockToChr
}
func (g *ProtocolInfoLMM) SetGenoBlockToChr(x []int) {
	g.genoBlockToChr = x
}
func (g *ProtocolInfoLMM) GetNumChrs() int {
	return g.numChrs
}
func (g *ProtocolInfoLMM) SetNumChrs(x int) {
	g.numChrs = x
}
func (g *ProtocolInfoLMM) SetPos(x []uint64) {
	g.pos = x
}
func (g *ProtocolInfoLMM) GetPos() []uint64 {
	return g.pos
}
func (g *ProtocolInfoLMM) GetLocalThreads() int {
	return g.config.LocalNumThreads
}
func (g *ProtocolInfoLMM) GetMpcAllThreads() int {
	return g.config.MpcNumThreads
}
func (g *ProtocolInfoLMM) GetMpcPerBlock() int {
	return g.config.MpcObjsPerBlock
}
func (g *ProtocolInfoLMM) GetMpcMainThreads() int {
	return g.config.MpcMainThreads
}
func (g *ProtocolInfoLMM) GetCalcGCapacity() int {
	return g.config.CalcGCapacity
}
