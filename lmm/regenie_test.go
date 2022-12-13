package lmm

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"

	"go.dedis.ch/onet/v3/log"

	"os"

	"github.com/BurntSushi/toml"
	"github.com/hhcho/sfgwas-lmm/gwas"
	"github.com/raulk/go-watchdog"
)

var reg *REGENIE

func NewRegenie() *REGENIE {
	// tab := '\t'
	// geno := gwas.LoadMatrixFromFile("../data/regenie-toy/geno.txt", tab)
	// fmt.Println(geno.Dims())

	// arguments := os.Args
	pid, _ := strconv.Atoi(os.Getenv("PID"))
	// pid, _ := strconv.Atoi(arguments[1])
	config := new(gwas.Config)
	// Import global parameters
	if _, err := toml.DecodeFile("../config/regenie/configGlobal.toml", config); err != nil {
		fmt.Println(err)
	}
	// Import local parameters
	if _, err := toml.DecodeFile(fmt.Sprintf("../config/regenie/configLocal.Party%d.toml", pid), config); err != nil {
		fmt.Println(err)
	}

	// Create cache/output directories
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(config.OutDir, 0755); err != nil {
		panic(err)
	}
	blockToChr := make([]int, 10)
	for i := 0; i < 10; i++ {
		blockToChr[i] = 0
	}
	general := gwas.InitializeLMMProtocol(config, pid)
	fmt.Println("REGENIE Loaded")
	return &REGENIE{
		general:            general,
		N:                  500,
		M:                  1000,
		B:                  10,
		R:                  5,
		Q:                  5,
		K:                  2,
		C:                  4,
		AllN:               500,
		num_iteration_lvl1: []int{25, 90, 115, 155, 200},
		num_iteration_lvl0: []int{30, 10, 10, 20, 80},
		lvl1_refresh_rate:  10,
		blockToChr:         blockToChr,
		useADMM:            true,
	}
}

func NewRegeniePartiesLungBench(configName string) *REGENIE {
	// arguments := os.Args
	pid, _ := strconv.Atoi(os.Getenv("PID"))
	// pid, _ := strconv.Atoi(arguments[1])
	config := new(gwas.Config)
	fmt.Println(configName)
	if _, err := toml.DecodeFile("../config/regenie/"+configName+"/configGlobal.toml", config); err != nil {
		fmt.Println(err)
	}

	// Import local parameters
	if _, err := toml.DecodeFile(fmt.Sprintf("../config/regenie/"+configName+"/configLocal.Party%d.toml", pid), config); err != nil {
		fmt.Println(err)
	}
	// Create cache/output directories
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(config.OutDir, 0755); err != nil {
		panic(err)
	}

	general := gwas.InitializeLMMProtocol(config, pid) // represents folds
	fmt.Println("REGENIE Loaded")

	runtime.GOMAXPROCS(config.LocalNumThreads)

	totalInds := 0
	for i := range config.NumInds {
		totalInds += config.NumInds[i]
	}
	fmt.Println("totalInds", totalInds)

	return &REGENIE{
		general:            general,
		num_iteration_lvl1: []int{25, 90, 115, 155, 200},
		num_iteration_lvl0: []int{30, 10, 10, 20, 80},
		lvl1_refresh_rate:  10,
		R:                  5,
		Q:                  5,
		useADMM:            true,
	}
}

func TestAllUKBOut(t *testing.T) {
	reg = NewRegeniePartiesLungBench("ukb_out")
	err, stopFn := watchdog.HeapDriven(reg.general.GetConfig().MemoryLimit, 40, watchdog.NewAdaptivePolicy(0.5))
	if err != nil {
		panic(err)
	}
	defer stopFn()
	parNet := reg.general.GetParallelNetwork()
	reg.useADMM = true
	runtime.GOMAXPROCS(reg.general.GetLocalThreads())
	reg.PrecomputeVals(true)
	parNet.ResetNetworkLog()

	reg.Level0()
	fmt.Println("Level0 Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()
	reg.general.GetMPC().AssertSync()
}

func TestAllLevel1UKBOut(t *testing.T) {
	reg = NewRegeniePartiesLungBench("ukb_out")
	err, stopFn := watchdog.HeapDriven(reg.general.GetConfig().MemoryLimit, 40, watchdog.NewAdaptivePolicy(0.5))
	if err != nil {
		panic(err)
	}
	defer stopFn()
	reg.useADMM = true
	parNet := reg.general.GetParallelNetwork()

	runtime.GOMAXPROCS(reg.general.GetLocalThreads())

	reg.PrecomputeVals(true)
	start := time.Now()
	parNet.ResetNetworkLog()
	reg.Level1()
	log.LLvl1(time.Now().Format(time.StampMilli), "Level1 time: ", time.Now().Sub(start).String())
	log.LLvl1(time.Now().Format(time.StampMilli), "Level1 Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()
	reg.general.GetMPC().AssertSync()
}

func TestAllAssocUKBOut(t *testing.T) {
	reg = NewRegeniePartiesLungBench("ukb_out")
	err, stopFn := watchdog.HeapDriven(reg.general.GetConfig().MemoryLimit, 40, watchdog.NewAdaptivePolicy(0.5))
	if err != nil {
		panic(err)
	}
	defer stopFn()
	reg.useADMM = true
	parNet := reg.general.GetParallelNetwork()
	runtime.GOMAXPROCS(reg.general.GetLocalThreads())

	reg.PrecomputeVals(false)
	parNet.ResetNetworkLog()

	yloco := reg.Load_Completed_YLOCO()
	start := time.Now()
	reg.AssociationStats(yloco)

	log.LLvl1(time.Now().Format(time.StampMilli), "Assoc time: ", time.Now().Sub(start).String())
	log.LLvl1(time.Now().Format(time.StampMilli), "Assoc Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()
	reg.general.GetMPC().AssertSync()
}
