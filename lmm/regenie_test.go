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
	pid, _ := strconv.Atoi(os.Getenv("PID"))
	config := new(gwas.Config)

	if _, err := toml.DecodeFile("../config/configGlobal.toml", config); err != nil {
		fmt.Println(err)
	}

	// Import local parameters
	if _, err := toml.DecodeFile(fmt.Sprintf("../config/configLocal.Party%d.toml", pid), config); err != nil {
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

func TestLevel0(t *testing.T) {
	reg = NewRegenie()

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
	start := time.Now()

	reg.Level0()

	log.LLvl1(time.Now().Format(time.StampMilli), "Level0 time: ", time.Now().Sub(start).String())
	log.LLvl1(time.Now().Format(time.StampMilli), "Level0 Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()

	reg.general.GetMPC().AssertSync()
}

func TestLevel1(t *testing.T) {
	reg = NewRegenie()

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
	start := time.Now()

	reg.Level1()

	log.LLvl1(time.Now().Format(time.StampMilli), "Level1 time: ", time.Now().Sub(start).String())
	log.LLvl1(time.Now().Format(time.StampMilli), "Level1 Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()

	reg.general.GetMPC().AssertSync()
}

func TestAssoc(t *testing.T) {
	reg = NewRegenie()

	err, stopFn := watchdog.HeapDriven(reg.general.GetConfig().MemoryLimit, 40, watchdog.NewAdaptivePolicy(0.5))
	if err != nil {
		panic(err)
	}
	defer stopFn()

	parNet := reg.general.GetParallelNetwork()
	reg.useADMM = true

	runtime.GOMAXPROCS(reg.general.GetLocalThreads())

	reg.PrecomputeVals(false)

	parNet.ResetNetworkLog()
	start := time.Now()

	yloco := reg.Load_Completed_YLOCO()
	reg.AssociationStats(yloco)

	log.LLvl1(time.Now().Format(time.StampMilli), "Assoc time: ", time.Now().Sub(start).String())
	log.LLvl1(time.Now().Format(time.StampMilli), "Assoc Network Log")
	parNet.PrintNetworkLog()
	parNet.ResetNetworkLog()

	reg.general.GetMPC().AssertSync()
}
