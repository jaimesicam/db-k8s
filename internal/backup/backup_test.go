package backup

import (
	"testing"
	"time"
)

// ---- status normalization ----

func TestNormalizePXCStatus(t *testing.T) {
	cases := map[string]Status{
		"Succeeded": StatusSucceeded,
		"Running":   StatusRunning,
		"Failed":    StatusFailed,
		"Error":     StatusFailed,
		"":          "",
		"weird":     StatusUnknown,
	}
	for in, want := range cases {
		if got := NormalizePXCStatus(in); got != want {
			t.Errorf("NormalizePXCStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePGStatus(t *testing.T) {
	cases := map[string]Status{
		"Succeeded": StatusSucceeded,
		"Running":   StatusRunning,
		"Failed":    StatusFailed,
	}
	for in, want := range cases {
		if got := NormalizePGStatus(in); got != want {
			t.Errorf("NormalizePGStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeMongoStatus(t *testing.T) {
	cases := map[string]Status{
		"ready":     StatusSucceeded,
		"succeeded": StatusSucceeded,
		"running":   StatusRunning,
		"error":     StatusFailed,
		"failed":    StatusFailed,
		"requested": StatusPending,
		"new":       StatusPending,
	}
	for in, want := range cases {
		if got := NormalizeMongoStatus(in); got != want {
			t.Errorf("NormalizeMongoStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- engine + kind mapping ----

func TestEngineFromKind(t *testing.T) {
	cases := map[string]Engine{
		"PerconaXtraDBClusterBackup":   EnginePXC,
		"PerconaXtraDBClusterRestore":  EnginePXC,
		"PerconaPGBackup":              EnginePostgres,
		"PerconaPGRestore":             EnginePostgres,
		"PerconaServerMongoDBBackup":   EngineMongoDB,
		"PerconaServerMongoDBRestore":  EngineMongoDB,
		"DatabaseClusterBackup":        EngineEverest,
		"DatabaseClusterRestore":       EngineEverest,
	}
	for kind, want := range cases {
		got, ok := EngineFromKind(kind)
		if !ok || got != want {
			t.Errorf("EngineFromKind(%q) = (%q,%v), want %q", kind, got, ok, want)
		}
	}
	if _, ok := EngineFromKind("Pod"); ok {
		t.Error("EngineFromKind(\"Pod\") should be ok=false")
	}
}

func TestIsRestoreKind(t *testing.T) {
	if !IsRestoreKind("PerconaPGRestore") {
		t.Error("PerconaPGRestore should be a restore")
	}
	if IsRestoreKind("PerconaPGBackup") {
		t.Error("PerconaPGBackup should not be a restore")
	}
}

// ---- timestamp parsing ----

func TestParseTimestampLogfmt(t *testing.T) {
	ts, ok := ParseTimestamp(`time="2026-05-28T10:59:49Z" level=info msg="crunchy-pgbackrest starts"`)
	if !ok {
		t.Fatal("expected to parse logfmt timestamp")
	}
	want := time.Date(2026, 5, 28, 10, 59, 49, 0, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("got %v, want %v", ts, want)
	}
}

func TestParseTimestampISO(t *testing.T) {
	ts, ok := ParseTimestamp("2026-05-28T11:08:15.123Z 0 [System] SST done")
	if !ok || ts.Minute() != 8 {
		t.Errorf("iso timestamp not parsed: ok=%v ts=%v", ok, ts)
	}
}

func TestParseTimestampXBScript(t *testing.T) {
	ts, ok := ParseTimestamp("2026-05-28 12:56:18.206  INFO: [SST script] Backup finished")
	if !ok {
		t.Fatal("expected to parse xb script timestamp")
	}
	if ts.Hour() != 12 || ts.Minute() != 56 {
		t.Errorf("unexpected ts: %v", ts)
	}
}

func TestParseTimestampMongoJSON(t *testing.T) {
	line := `{"t":{"$date":"2026-05-28T11:14:29.730+00:00"},"s":"I","c":"ACCESS"}`
	ts, ok := ParseTimestamp(line)
	if !ok {
		t.Fatal("expected to parse mongo JSON timestamp")
	}
	if ts.Year() != 2026 {
		t.Errorf("unexpected ts: %v", ts)
	}
}

func TestParseTimestampNoMatch(t *testing.T) {
	if _, ok := ParseTimestamp("a line with no timestamp"); ok {
		t.Error("expected ok=false")
	}
}

// ---- log classification ----

func TestClassifyXtrabackupSuccess(t *testing.T) {
	cases := []string{
		"+ log INFO 'Backup was finished successfully'",
		"2026-05-28 11:08:13.517  INFO: sst-script finished with code (wait): 0",
		"2026-05-28 11:08:12.486  INFO: SST script ended gracefully",
	}
	for _, line := range cases {
		v := ClassifyXtrabackupLine(line)
		if v.Outcome != StatusSucceeded {
			t.Errorf("expected Succeeded for %q, got outcome=%q type=%q", line, v.Outcome, v.Type)
		}
	}
}

func TestClassifyXtrabackupFailure(t *testing.T) {
	cases := []string{
		"SST_FAILED",
		"xbcloud: error uploading chunk",
		"xtrabackup: error initializing",
		"Backup failed",
	}
	for _, line := range cases {
		v := ClassifyXtrabackupLine(line)
		if v.Outcome != StatusFailed {
			t.Errorf("expected Failed for %q, got %q", line, v.Outcome)
		}
	}
}

func TestClassifyPgBackRestSuccess(t *testing.T) {
	v := ClassifyPgBackRestLine(`time="2026-05-28T10:59:56Z" level=info msg="crunchy-pgbackrest ends"`)
	if v.Outcome != StatusSucceeded {
		t.Errorf("expected Succeeded, got %q", v.Outcome)
	}
}

func TestClassifyPgBackRestFatal(t *testing.T) {
	v := ClassifyPgBackRestLine(`time="2026-05-28T10:59:08Z" level=fatal msg="command terminated with exit code 1"`)
	if v.Outcome != StatusFailed {
		t.Errorf("expected Failed, got %q", v.Outcome)
	}
	if v.Type != EventBackupFailed {
		t.Errorf("expected backup_failed, got %q", v.Type)
	}
}

func TestClassifyPgBackRestWarningDoesNotFlipSuccess(t *testing.T) {
	v := ClassifyPgBackRestLine(`time="2026-05-28T10:59:49Z" level=info msg="[pgbackrest:stdout] 2026-05-28 10:59:49.216 P00   WARN: option 'repo1-retention-full' is not set"`)
	if !v.IsWarning {
		t.Error("expected IsWarning=true for WARN: line")
	}
	if v.Outcome == StatusFailed {
		t.Error("WARN: line should not flip outcome to Failed")
	}
}

func TestClassifyPgBackRestStderrIsWarning(t *testing.T) {
	v := ClassifyPgBackRestLine(`time="2026-05-28T10:59:08Z" level=info msg="[pgbackrest:stderr] hash 41fcb0bfc5d  - does not match local hash bcbc615c"`)
	if !v.IsWarning {
		t.Error("expected pgbackrest:stderr line to be marked as warning")
	}
}

// ---- pod-name correlation ----

func TestPXCPodKey(t *testing.T) {
	got, ok := PXCPodKey("xb-backup-ehs-dsblr")
	if !ok || got != "backup-ehs" {
		t.Errorf("PXCPodKey(\"xb-backup-ehs-dsblr\") = (%q,%v), want backup-ehs,true", got, ok)
	}
	if _, ok := PXCPodKey("postgresql-awn-backup-k5pr-875zc"); ok {
		t.Error("PXCPodKey should reject postgres-shaped pod name")
	}
}

func TestPGPodKey(t *testing.T) {
	got, ok := PGPodKey("postgresql-awn-backup-k5pr-875zc")
	if !ok || got != "postgresql-awn-backup-k5pr" {
		t.Errorf("PGPodKey = (%q,%v), want postgresql-awn-backup-k5pr,true", got, ok)
	}
}

// ---- Operation.Duration ----

func TestOperationDuration(t *testing.T) {
	op := Operation{
		Started: time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC), HasStart: true,
		Completed: time.Date(2026, 5, 28, 10, 1, 23, 0, time.UTC), HasFinish: true,
	}
	if d := op.Duration(); d != "1m23s" {
		t.Errorf("expected 1m23s, got %q", d)
	}
	op.HasFinish = false
	if d := op.Duration(); d != "" {
		t.Errorf("expected empty duration when HasFinish=false, got %q", d)
	}
}
