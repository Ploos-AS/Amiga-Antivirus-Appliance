package historical

// InitialEngines returns the M8 compatibility targets. These entries describe
// user-supplied historical software; AAA does not redistribute the binaries.
func InitialEngines() []Engine {
	return []Engine{
		{ID: "mill", Name: "Mill", ExpectedVersion: "0.85", SupportedProfiles: []OSProfile{OS204, OS31}},
		{ID: "viruschecker2", Name: "VirusChecker II", ExpectedVersion: "2.5", SupportedProfiles: []OSProfile{OS204, OS31}},
		{ID: "virusexecutor", Name: "VirusExecutor", ExpectedVersion: "2.34", SupportedProfiles: []OSProfile{OS204, OS31, OS32}},
		{ID: "virusslayer2", Name: "VirusSlayer II", ExpectedVersion: "1.0b", SupportedProfiles: []OSProfile{OS204, OS31}},
		{ID: "virusz3", Name: "VirusZ III", ExpectedVersion: "1.04ß", SupportedProfiles: []OSProfile{OS204, OS31, OS32}},
		{ID: "vtschutz", Name: "VT-Schutz", ExpectedVersion: "3.17", SupportedProfiles: []OSProfile{OS13}},
	}
}

func InitialRegistry() (*Registry, error) {
	return NewRegistry(InitialEngines()...)
}
