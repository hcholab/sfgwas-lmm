package gwas

import "C"
import (
	"github.com/hhcho/sfgwas-lmm/mpc"
)

type Config struct {
	NumMainParties int `toml:"num_main_parties"`
	HubPartyId     int `toml:"hub_party_id"`

	CkksParams string `toml:"ckks_params"`

	divSqrtMaxLen int `toml:"div_sqrt_max_len"`

	NumInds []int `toml:"num_inds"`
	NumSnps int   `toml:"num_snps"`
	NumCovs int   `toml:"num_covs"`

	ItersPerEval  int `toml:"iter_per_eigenval"`
	NumPCs        int `toml:"num_pcs_to_remove"`
	NumOversample int `toml:"num_oversampling"`
	NumPowerIters int `toml:"num_power_iters"`

	SkipQC       bool `toml:"skip_qc"`
	SkipPCA      bool `toml:"skip_pca"`
	UseCachedQC  bool `toml:"use_cached_qc"`
	UseCachedPCA bool `toml:"use_cached_pca"`

	IndMissUB    float64 `toml:"imiss_ub"`
	HetLB        float64 `toml:"het_lb"`
	HetUB        float64 `toml:"het_ub"`
	SnpMissUB    float64 `toml:"gmiss"`
	MafLB        float64 `toml:"maf_lb"`
	HweUB        float64 `toml:"hwe_ub"`
	SnpDistThres int     `toml:"snp_dist_thres"`

	Servers map[string]mpc.Server

	SharedKeysPath string `toml:"shared_keys_path"`

	GenoBinFilePrefix    string `toml:"geno_binary_file_prefix"`
	GenoNumFolds         int    `toml:"geno_num_folds"`
	GenoNumBlocks        int    `toml:"geno_num_blocks"`
	GenoFoldSizeFile     string `toml:"geno_fold_size_file"`
	GenoBlockSizeFile    string `toml:"geno_block_size_file"`
	GenoBlockToChromFile string `toml:"geno_block_to_chrom_file"`
	GenoCountFile        string `toml:"geno_count_file"`
	PhenoFile            string `toml:"pheno_file"`
	CovFile              string `toml:"covar_file"`
	SnpPosFile           string `toml:"snp_position_file"`

	Step2NumSnps       int `toml:"step_2_num_snps"`
	Step2GenoNumBlocks int `toml:"step_2_geno_num_blocks"`

	Step2GenoBinFilePrefix    string `toml:"step_2_geno_binary_file_prefix"`
	Step2GenoBlockSizeFile    string `toml:"step_2_geno_block_size_file"`
	Step2GenoBlockToChromFile string `toml:"step_2_geno_block_to_chrom_file"`
	Step2GenoCountFile        string `toml:"step_2_geno_count_file"`
	Step2SnpPosFile           string `toml:"step_2_snp_position_file"`

	OutDir   string `toml:"output_dir"`
	CacheDir string `toml:"cache_dir"`

	MpcFieldSize    int    `toml:"mpc_field_size"`
	MpcDataBits     int    `toml:"mpc_data_bits"`
	MpcFracBits     int    `toml:"mpc_frac_bits"`
	MpcNumThreads   int    `toml:"mpc_num_threads"`
	MpcObjsPerBlock int    `toml:"mpc_objs_per_block"`
	MpcMainThreads  int    `toml:"mpc_num_main_threads"`
	LocalNumThreads int    `toml:"local_num_threads"`
	CalcGCapacity   int    `toml:"calc_g_capacity"`
	MemoryLimit     uint64 `toml:"memory_limit"`

	Debug bool `toml:"debug"`
}
