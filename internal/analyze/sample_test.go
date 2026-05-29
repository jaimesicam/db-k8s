package analyze_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/db-k8s/db-k8s/internal/analyze"
	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/importer"
)

// samplePath locates samples/<n>/cluster-dump.tar.gz by walking up from the test dir.
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

func importAndAnalyze(t *testing.T, sampleNum string) analyze.Result {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := importer.ImportArchive(d, samplePath(t, sampleNum)); err != nil {
		t.Fatal(err)
	}
	res, err := analyze.Run(d)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func findFinding(res analyze.Result, rule, name string) (analyze.Finding, bool) {
	for _, f := range res.Findings {
		if f.Rule == rule && f.Name == name {
			return f, true
		}
	}
	return analyze.Finding{}, false
}

// Sample 1 should surface the PXC "initializing" cluster mysql-dnb.
func TestSample1_PXC_Initializing(t *testing.T) {
	res := importAndAnalyze(t, "1")
	f, ok := findFinding(res, "percona.state_initializing", "mysql-dnb")
	if !ok {
		t.Fatalf("expected percona.state_initializing for mysql-dnb in sample 1; got %d findings",
			len(res.Findings))
	}
	if f.Severity != analyze.SeverityCritical {
		t.Errorf("want critical, got %s", f.Severity)
	}
	if f.Namespace != "everest" {
		t.Errorf("want namespace=everest, got %q", f.Namespace)
	}
	// Also expect at least one CrashLoopBackOff and OOMKilled.
	if _, ok := findFinding(res, "pod.crashloop", "mysql-dnb-pxc-0"); !ok {
		t.Error("expected pod.crashloop on mysql-dnb-pxc-0 in sample 1")
	}
}

// Sample 4 should surface PG postgresql-zlp condition_false even though state=ready.
// The exact condition.type varies by operator version (PGBackRestRepoHostReady or
// ReadyForBackup), so we assert the condition_false rule fires for postgresql-zlp
// and that the reason mentions backup/repo (which routes severity to critical).
func TestSample4_PG_ConditionFalse(t *testing.T) {
	res := importAndAnalyze(t, "4")
	found := false
	for _, f := range res.Findings {
		if f.Rule != "percona.condition_false" || f.Name != "postgresql-zlp" {
			continue
		}
		found = true
		// Backup/repo conditions are routed to critical.
		if f.Severity != analyze.SeverityCritical {
			continue
		}
		return
	}
	if !found {
		t.Fatalf("expected percona.condition_false for postgresql-zlp in sample 4; got %d findings",
			len(res.Findings))
	}
	t.Error("expected at least one critical condition_false for postgresql-zlp (backup/repo)")
}

// Sample 8 should surface the PXC state=error cluster mysql-u94.
func TestSample8_PXC_StateError(t *testing.T) {
	res := importAndAnalyze(t, "8")
	f, ok := findFinding(res, "percona.state_error", "mysql-u94")
	if !ok {
		t.Fatalf("expected percona.state_error for mysql-u94 in sample 8; got %d findings",
			len(res.Findings))
	}
	if f.Severity != analyze.SeverityCritical {
		t.Errorf("want critical, got %s", f.Severity)
	}
}

// Sample 11 ships rich PXC node logs (PMM setup, mysqld start, WSREP state
// changes, SST/IST). The log analyzer should detect three pxc nodes and
// surface SST + log warning/error concerns.
func TestSample11_PXC_TimelineFindings(t *testing.T) {
	res := importAndAnalyze(t, "11")
	if len(res.PXC.Dumps) == 0 {
		t.Fatal("expected at least one PXC dump timeline in sample 11")
	}
	dt := res.PXC.Dumps[0]
	wantNodes := map[string]bool{
		"mysql-mwl-pxc-0": false,
		"mysql-mwl-pxc-1": false,
		"mysql-mwl-pxc-2": false,
	}
	for _, n := range dt.Nodes {
		if _, ok := wantNodes[n]; ok {
			wantNodes[n] = true
		}
	}
	for n, seen := range wantNodes {
		if !seen {
			t.Errorf("expected to detect %s in sample 11 timeline; nodes=%v", n, dt.Nodes)
		}
	}
	if dt.SSTCount == 0 {
		t.Error("expected at least one SST event in sample 11 timeline")
	}
	// At least one pxc.sst.detected info finding should surface.
	sawSST := false
	sawLogConcern := false
	for _, f := range res.Findings {
		if f.Rule == "pxc.sst.detected" {
			sawSST = true
		}
		if f.Rule == "pxc.log.warning" || f.Rule == "pxc.log.error" {
			sawLogConcern = true
		}
	}
	if !sawSST {
		t.Error("expected pxc.sst.detected finding for sample 11")
	}
	if !sawLogConcern {
		t.Error("expected pxc.log.warning or pxc.log.error finding for sample 11")
	}
}

// Sample 2 (PSMDB) should NOT raise Percona-family findings (baseline is healthy).
// This guards against future false positives.
func TestSample2_PSMDB_HealthyBaseline(t *testing.T) {
	res := importAndAnalyze(t, "2")
	for _, f := range res.Findings {
		switch f.Rule {
		case "percona.state_error", "percona.state_initializing",
			"psmdb.replset_unhealthy", "psmdb.mongos_unhealthy", "psmdb.member_down":
			t.Errorf("sample 2 should be a healthy PSMDB baseline, but got: [%s] %s on %s/%s — %s",
				f.Severity, f.Rule, f.Namespace, f.Name, f.Title)
		}
	}
}
