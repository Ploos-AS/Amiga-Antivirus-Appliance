package signaturefactory

import "testing"

func TestParseClamAVVersion(t *testing.T) {
	engine, db, err := ParseClamAVVersion("ClamAV 1.4.3/27500/Fri Sep 5 12:00:00 2026")
	if err != nil {
		t.Fatalf("ParseClamAVVersion: %v", err)
	}
	if engine != "1.4.3" {
		t.Fatalf("engine = %q", engine)
	}
	if db != "27500" {
		t.Fatalf("db = %q", db)
	}
}

func TestParseClamAVVersionRequiresDatabaseVersion(t *testing.T) {
	if _, _, err := ParseClamAVVersion("ClamAV 1.4.3"); err == nil {
		t.Fatal("expected missing database version to fail")
	}
}

func TestParseClamAVResultLineFound(t *testing.T) {
	name, found, err := ParseClamAVResultLine("sample.adf: Test.Amiga.BootVirus FOUND")
	if err != nil {
		t.Fatalf("ParseClamAVResultLine: %v", err)
	}
	if !found || name != "Test.Amiga.BootVirus" {
		t.Fatalf("found=%t name=%q", found, name)
	}
}

func TestParseClamAVResultLineCleanIsNotEvidence(t *testing.T) {
	name, found, err := ParseClamAVResultLine("sample.adf: OK")
	if err != nil {
		t.Fatalf("ParseClamAVResultLine: %v", err)
	}
	if found || name != "" {
		t.Fatalf("found=%t name=%q", found, name)
	}
}

func TestNewClamAVEvidence(t *testing.T) {
	evidence, err := NewClamAVEvidence(ClamAVDetection{
		DetectionName:      "Test.Amiga.BootVirus",
		EngineVersion:      "1.4.3",
		SignatureDBVersion: "27500",
		RawResult:          "sample.adf: Test.Amiga.BootVirus FOUND",
	})
	if err != nil {
		t.Fatalf("NewClamAVEvidence: %v", err)
	}
	if evidence.SourceEngine != "clamav" {
		t.Fatalf("source engine = %q", evidence.SourceEngine)
	}
	if evidence.SourceVersion != "1.4.3" {
		t.Fatalf("source version = %q", evidence.SourceVersion)
	}
	if evidence.SignatureDBVersion != "27500" {
		t.Fatalf("db version = %q", evidence.SignatureDBVersion)
	}
	if evidence.CorrelationKey != "clamav-db:27500" {
		t.Fatalf("correlation key = %q", evidence.CorrelationKey)
	}
}

func TestNewClamAVEvidenceFailsClosedWithoutDatabaseIdentity(t *testing.T) {
	_, err := NewClamAVEvidence(ClamAVDetection{
		DetectionName: "Test.Amiga.BootVirus",
		EngineVersion: "1.4.3",
	})
	if err == nil {
		t.Fatal("expected missing database identity to fail")
	}
}

func TestClamAVCorrelationUsesDatabaseIdentity(t *testing.T) {
	first, err := NewClamAVEvidence(ClamAVDetection{
		DetectionName:      "Test.One",
		EngineVersion:      "1.4.3",
		SignatureDBVersion: "27500",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewClamAVEvidence(ClamAVDetection{
		DetectionName:      "Test.Two",
		EngineVersion:      "1.4.4",
		SignatureDBVersion: "27500",
	})
	if err != nil {
		t.Fatal(err)
	}
	count, err := IndependentEvidenceSources([]Evidence{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("independent sources = %d, want 1", count)
	}
}
