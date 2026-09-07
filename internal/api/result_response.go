package api

import (
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
	archivepkg "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/archive"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/engineevidence"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/hunk"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/preservation"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/scanner"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
)

// resultResponse is the public REST representation of scanner.Result.
// It deliberately whitelists fields and never exposes scanner.Result.Path,
// which contains an appliance-local filesystem path.
type resultResponse struct {
	Name              string                  `json:"name"`
	Size              int64                   `json:"size"`
	SHA256            string                  `json:"sha256"`
	Format            string                  `json:"format"`
	Verdict           string                  `json:"verdict"`
	Detection         string                  `json:"detection,omitempty"`
	EngineResults     []engineevidence.Result `json:"engine_results,omitempty"`
	Archive           *archivepkg.Analysis    `json:"archive,omitempty"`
	PreservationImage *preservation.Analysis  `json:"preservation_image,omitempty"`
	MemberResults     []scanner.MemberResult  `json:"member_results,omitempty"`
	ADF               *adf.Analysis           `json:"adf,omitempty"`
	Filesystem        *adf.FilesystemAnalysis `json:"filesystem,omitempty"`
	Hunk              *hunk.Analysis          `json:"hunk,omitempty"`
	BootblockMatch    *signatures.Match       `json:"bootblock_match,omitempty"`
}

func resultResponseFrom(result scanner.Result) resultResponse {
	return resultResponse{
		Name:              result.Name,
		Size:              result.Size,
		SHA256:            result.SHA256,
		Format:            result.Format,
		Verdict:           result.Verdict,
		Detection:         result.Detection,
		EngineResults:     result.EngineResults,
		Archive:           result.Archive,
		PreservationImage: result.PreservationImage,
		MemberResults:     result.MemberResults,
		ADF:               result.ADF,
		Filesystem:        result.Filesystem,
		Hunk:              result.Hunk,
		BootblockMatch:    result.BootblockMatch,
	}
}
