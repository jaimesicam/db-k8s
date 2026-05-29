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

// sample11Path returns the path to sample 11's tar.gz, which contains rich PXC
// node logs (PMM setup, mysqld start, WSREP state changes, SST/IST, donor and
// joiner flows). Tests for the PXC timeline are anchored on this fixture.
func sample11Path(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "samples", "11", "cluster-dump.tar.gz")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("samples/11 not found")
	return ""
}

func setupWithSample11(t *testing.T) (*db.DB, string) {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := importer.ImportArchive(d, sample11Path(t)); err != nil {
		t.Fatal(err)
	}
	return d, tmp
}

func TestTimelinePageGenerated(t *testing.T) {
	d, tmp := setupWithSample11(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "pxc-timeline.html"))
	if err != nil {
		t.Fatalf("pxc-timeline.html missing: %v", err)
	}
	s := string(body)
	for _, expected := range []string{
		"PXC Timeline",
		"mysql-mwl-pxc-0",
		"mysql-mwl-pxc-1",
		"mysql-mwl-pxc-2",
		"server_status_change",
		"sst_completed",
		"wsrep_ready",
	} {
		if !strings.Contains(s, expected) {
			t.Errorf("pxc-timeline.html missing expected %q", expected)
		}
	}
}

func TestTimelineEventLinksResolve(t *testing.T) {
	d, tmp := setupWithSample11(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "pxc-timeline.html"))
	if err != nil {
		t.Fatal(err)
	}
	// Find a representative file href like files/file-7.html#line-1085
	fileRe := regexp.MustCompile(`href="(files/file-(\d+)\.html#line-(\d+))"`)
	matches := fileRe.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Fatal("timeline page has no per-event file links")
	}
	checked := 0
	for _, m := range matches {
		fileHref, fileID, line := m[1], m[2], m[3]
		// Strip the fragment; we only need to verify the page exists.
		page := strings.SplitN(fileHref, "#", 2)[0]
		pagePath := filepath.Join(outDir, page)
		pageBody, err := os.ReadFile(pagePath)
		if err != nil {
			t.Errorf("event link target %s missing for file %s: %v", pagePath, fileID, err)
			continue
		}
		// The rendered file page should have a line anchor span for this line.
		want := fmt.Sprintf(`id="line-%s"`, line)
		if !strings.Contains(string(pageBody), want) {
			t.Errorf("file %s has no anchor %s", fileID, want)
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

func TestTimelineRawLinksResolve(t *testing.T) {
	d, tmp := setupWithSample11(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "pxc-timeline.html"))
	if err != nil {
		t.Fatal(err)
	}
	rawRe := regexp.MustCompile(`href="(raw/dump-\d+/[^"]+)"`)
	matches := rawRe.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		t.Fatal("timeline page has no raw links")
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

func TestFilePageHasLineAnchors(t *testing.T) {
	d, tmp := setupWithSample11(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	// Pick the first text/log file and confirm it has id="line-1" and id="line-2".
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	var chosen int64
	for _, f := range files {
		if strings.HasSuffix(f.RelativePath, "/logs.txt") {
			chosen = f.ID
			break
		}
	}
	if chosen == 0 {
		t.Skip("no logs.txt in sample")
	}
	page := filepath.Join(outDir, "files", fmt.Sprintf("file-%d.html", chosen))
	body, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []string{`id="line-1"`, `id="line-2"`} {
		if !strings.Contains(string(body), anchor) {
			t.Errorf("file page missing %s", anchor)
		}
	}
}

func TestIndexLinksToTimeline(t *testing.T) {
	d, tmp := setupWithSample11(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "pxc-timeline.html") {
		t.Error("index.html should link to pxc-timeline.html")
	}
}
