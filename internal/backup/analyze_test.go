package backup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/db-k8s/db-k8s/internal/backup"
	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/importer"
)

// samplePath locates samples/<n>/cluster-dump.tar.gz by walking up.
func samplePath(t *testing.T, n string) string {
	t.Helper()
	wd, _ := os.Getwd()
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "samples", n, "cluster-dump.tar.gz")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("sample %s not found", n)
	return ""
}

func importAndAnalyze(t *testing.T, n string) backup.AnalysisResult {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := importer.ImportArchive(d, samplePath(t, n)); err != nil {
		t.Fatal(err)
	}
	res, err := backup.Analyze(d)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// PXC samples that have non-empty backup CRDs.
func TestSample1_PXC_BackupSucceeded(t *testing.T) {
	res := importAndAnalyze(t, "1")
	op, ok := findOp(res, backup.EnginePXC, "backup-ehs")
	if !ok {
		t.Fatalf("expected PXC backup-ehs in sample 1; got %d ops", len(res.Operations))
	}
	if op.Status != backup.StatusSucceeded {
		t.Errorf("expected Succeeded, got %q", op.Status)
	}
	if op.Cluster != "mysql-n52" {
		t.Errorf("expected cluster mysql-n52, got %q", op.Cluster)
	}
	if op.Storage == "" || op.Destination == "" {
		t.Errorf("expected storage+destination populated: storage=%q dest=%q", op.Storage, op.Destination)
	}
	// Backup pod logs should have contributed a backup_completed event.
	if !hasEventType(op, backup.EventBackupCompleted) {
		t.Errorf("expected at least one backup_completed event from logs")
	}
}

// Postgres sample with both Failed and Succeeded backups.
func TestSample4_Postgres_FailedAndSucceeded(t *testing.T) {
	res := importAndAnalyze(t, "4")
	failed, ok := findOp(res, backup.EnginePostgres, "backup-i5a")
	if !ok {
		t.Fatal("expected Postgres backup-i5a in sample 4")
	}
	if failed.Status != backup.StatusFailed {
		t.Errorf("backup-i5a should be Failed, got %q", failed.Status)
	}
	// The Succeeded backup has a generated name with a random suffix.
	hasSucceeded := false
	for _, op := range res.Operations {
		if op.Engine != backup.EnginePostgres {
			continue
		}
		if strings.HasPrefix(op.Name, "postgresql-awn-backup-k5pr-") && op.Status == backup.StatusSucceeded {
			hasSucceeded = true
		}
	}
	if !hasSucceeded {
		t.Error("expected at least one Succeeded Postgres backup with prefix postgresql-awn-backup-k5pr-")
	}
	// fatal log should produce a backup.log_error finding.
	if !hasFindingRule(res, "backup.log_error") {
		t.Error("expected backup.log_error finding from pgbackrest fatal log")
	}
}

// Mongo sample (CRD-only, no backup pod log channel).
func TestSample2_Mongo_BackupCR(t *testing.T) {
	res := importAndAnalyze(t, "2")
	op, ok := findOp(res, backup.EngineMongoDB, "backup-b7f")
	if !ok {
		t.Fatalf("expected MongoDB backup-b7f in sample 2; got %d ops", len(res.Operations))
	}
	if op.Status != backup.StatusSucceeded {
		t.Errorf("MongoDB backup-b7f should map ready→Succeeded, got %q", op.Status)
	}
	if op.Cluster != "mongodb-3gf" {
		t.Errorf("expected cluster mongodb-3gf, got %q", op.Cluster)
	}
}

// Sample 11 has no backup CRDs of any kind.
func TestSample11_NoBackups(t *testing.T) {
	res := importAndAnalyze(t, "11")
	if len(res.Operations) != 0 {
		t.Errorf("expected zero backup operations in sample 11, got %d", len(res.Operations))
	}
}

// Every backup event sourced from a log line must carry FileID + LineNumber.
func TestEventsPreserveFileIDLineNumber(t *testing.T) {
	res := importAndAnalyze(t, "1")
	saw := 0
	for _, op := range res.Operations {
		for _, ev := range op.Events {
			// Only log-line events have line numbers; CRD/Job events may not.
			if ev.LineNumber == 0 {
				continue
			}
			saw++
			if ev.FileID == 0 {
				t.Errorf("event with line number %d but no file id: %+v", ev.LineNumber, ev)
			}
		}
	}
	if saw == 0 {
		t.Error("expected at least one log-sourced event with a line number")
	}
}

// Walk every sample without crashing — guards future schema/log changes.
func TestAllSamplesSucceed(t *testing.T) {
	for _, n := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"} {
		t.Run(n, func(t *testing.T) {
			if _, err := os.Stat(samplePath(t, n)); err != nil {
				t.Skipf("sample %s missing", n)
			}
			res := importAndAnalyze(t, n)
			// At minimum the call must succeed and return a sortable result.
			_ = res.CountByEngineStatus()
		})
	}
}

// --- helpers ---

func findOp(res backup.AnalysisResult, engine backup.Engine, name string) (backup.Operation, bool) {
	for _, op := range res.Operations {
		if op.Engine == engine && op.Name == name {
			return op, true
		}
	}
	return backup.Operation{}, false
}

func hasEventType(op backup.Operation, t backup.EventType) bool {
	for _, ev := range op.Events {
		if ev.Type == t {
			return true
		}
	}
	return false
}

func hasFindingRule(res backup.AnalysisResult, rule string) bool {
	for _, f := range res.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
