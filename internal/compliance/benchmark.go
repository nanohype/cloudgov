package compliance

// Benchmark defines a compliance benchmark and its controls.
type Benchmark struct {
	ID       string
	Name     string
	Controls []Control
}

// AvailableBenchmarks returns the list of supported benchmark IDs.
func AvailableBenchmarks() []string {
	return []string{"cis-aws-v3", "cis-gcp-v2", "cis-azure-v2", "soc2"}
}

// GetBenchmark returns the benchmark definition for the given ID, or nil if not found.
func GetBenchmark(id string) *Benchmark {
	switch id {
	case "cis-aws-v3":
		return cisAWSv3Benchmark()
	case "cis-gcp-v2":
		return cisGCPv2Benchmark()
	case "cis-azure-v2":
		return cisAzureV2Benchmark()
	case "soc2":
		return soc2TypeIIBenchmark()
	default:
		return nil
	}
}
