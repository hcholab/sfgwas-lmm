package gwas

type FilterParams struct {
	MafLowerBound float64
	HweUpperBound float64
	GenoMissBound float64
	IndMissBound  float64
	HetLowerBound float64
	HetUpperBound float64
}

type GWASParams struct {
	numInds    []int
	numCovs    int
	numSnps    int
	numSnpsPCA int
	numPCs     int

	numFiltInds []int
	numFiltSnps int

	minSnpDist uint64

	skipQC bool
	runPCA bool // LMM or PCA
}

func InitGWASParams(numInds []int, numSnps, numCovs, numPCs, minSnpDist int) *GWASParams {
	gwasParams := &GWASParams{
		numInds:    numInds,
		numSnps:    numSnps,
		numCovs:    numCovs,
		numPCs:     numPCs,
		minSnpDist: uint64(minSnpDist),
	}
	return gwasParams
}
