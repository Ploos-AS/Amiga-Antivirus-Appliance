package support

import "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"

// EngineEvidenceComponents converts qualified M8.7 support provenance into the
// common M10.2 engine evidence component shape without changing identity.
func EngineEvidenceComponents(components []Component) ([]engineevidence.Component, error) {
	out := make([]engineevidence.Component, 0, len(components))
	for _, component := range components {
		if err := component.Validate(); err != nil {
			return nil, err
		}
		out = append(out, engineevidence.Component{
			Kind:    string(component.Kind),
			Name:    component.Name,
			Version: component.Version,
			SHA256:  component.SHA256,
			Source:  component.Source,
		})
	}
	return out, nil
}
