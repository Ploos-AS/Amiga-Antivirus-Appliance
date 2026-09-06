package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signaturefactory"
)

func main() {
	offset := int64(64)
	candidate, err := signaturefactory.NewPatternCandidate(signaturefactory.PatternCandidateInput{
		Family:        "BridgeFixture",
		MalwareName:   "AAA AmiGuard Bridge Fixture",
		SampleSHA256:  strings.Repeat("a", 64),
		SampleSize:    901120,
		Format:        "adf",
		Pattern:       signaturefactory.FixedPattern{BytesHex: "414d494755415244", Offset: &offset},
		SourceEngine:  "aaa-cross-repo-ci",
		SourceVersion: "1",
		OSProfile:     "os13",
		DetectionName: "AAA.Bridge.Fixture",
		Confidence:    signaturefactory.ConfidenceCorroborated,
		CreatedAt:     time.Date(2026, 9, 6, 19, 45, 0, 0, time.UTC),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create bridge fixture candidate: %v\n", err)
		os.Exit(1)
	}
	data, err := signaturefactory.MarshalAmiGuardResearch(candidate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal AmiGuard bridge fixture: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "write AmiGuard bridge fixture: %v\n", err)
		os.Exit(1)
	}
}
