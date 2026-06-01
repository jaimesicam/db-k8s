package report_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/importer"
	"github.com/db-k8s/db-k8s/internal/report"
)

// sample4Path is the richest backup fixture: it has both a Failed PXC-style
// backup CRD (postgresql) AND a Succeeded one in the same dump.
func sample4Path(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "samples", "4", "cluster-dump.tar.gz")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("samples/4 not found")
	return ""
}

func setupWithSample4(t *testing.T) (*db.DB, string) {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := importer.ImportArchive(d, sample4Path(t)); err != nil {
		t.Fatal(err)
	}
	return d, tmp
}

func TestBackupsPageGenerated(t *testing.T) {
	d, tmp := setupWithSample4(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "backups.html"))
	if err != nil {
		t.Fatalf("backups.html missing: %v", err)
	}
	s := string(body)
	for _, expected := range []string{
		"Backups",
		"PostgreSQL Backups",
		"bk-Succeeded",
		"bk-Failed",
		"backup-i5a",
	} {
		if !strings.Contains(s, expected) {
			t.Errorf("backups.html missing expected %q", expected)
		}
	}
}

func TestBackupEventLinksResolve(t *testing.T) {
	d, tmp := setupWithSample4(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "backups.html"))
	if err != nil {
		t.Fatal(err)
	}
	// Event link form: files/file-N.html#line-M
	re := regexp.MustCompile(`href="(files/file-(\d+)\.html#line-(\d+))"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Fatal("backups.html has no per-event file links")
	}
	checked := 0
	for _, m := range matches {
		fileHref, fileID, line := m[1], m[2], m[3]
		page := strings.SplitN(fileHref, "#", 2)[0]
		pagePath := filepath.Join(outDir, page)
		pageBody, err := os.ReadFile(pagePath)
		if err != nil {
			t.Errorf("event link target %s missing for file %s: %v", pagePath, fileID, err)
			continue
		}
		anchor := fmt.Sprintf(`id="line-%s"`, line)
		if !strings.Contains(string(pageBody), anchor) {
			t.Errorf("file %s has no anchor %s", fileID, anchor)
		}
		checked++
		if checked >= 20 {
			break
		}
	}
	if checked == 0 {
		t.Error("no event links could be verified")
	}
}

func TestBackupRawLinksResolve(t *testing.T) {
	d, tmp := setupWithSample4(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "backups.html"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`href="(raw/dump-\d+/[^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Fatal("backups.html has no raw links")
	}
	for i, m := range matches {
		if i > 30 {
			break
		}
		raw := m[1]
		if _, err := os.Stat(filepath.Join(outDir, raw)); err != nil {
			t.Errorf("raw link %s does not exist: %v", raw, err)
		}
	}
}

func TestIndexLinksToBackups(t *testing.T) {
	d, tmp := setupWithSample4(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "backups.html") {
		t.Error("index.html should link to backups.html")
	}
}

func TestBackupContributionsOnFilePage(t *testing.T) {
	d, tmp := setupWithSample4(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	// At least one of the postgresql-awn-backup-k5pr-* pod logs should have
	// a "Backup timeline contributions" block on its file detail page.
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	saw := 0
	for _, f := range files {
		if !strings.Contains(f.RelativePath, "postgresql-awn-backup-k5pr-") ||
			!strings.HasSuffix(f.RelativePath, "/logs.txt") {
			continue
		}
		page := filepath.Join(outDir, "files", fmt.Sprintf("file-%d.html", f.ID))
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "Backup timeline contributions") {
			saw++
		}
	}
	if saw == 0 {
		t.Error("expected at least one pg-backup pod log page to show backup contributions")
	}
}
