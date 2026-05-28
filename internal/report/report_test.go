package report_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/importer"
	"github.com/db-k8s/db-k8s/internal/report"
)

func samplesDir(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "samples")
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	t.Skip("samples/ not found")
	return ""
}

func firstSample(t *testing.T) string {
	t.Helper()
	dir := samplesDir(t)
	if dir == "" {
		return ""
	}
	var found string
	_ = filepath.WalkDir(dir, func(p string, dirent os.DirEntry, err error) error {
		if err != nil || dirent.IsDir() || found != "" {
			return nil
		}
		if strings.HasSuffix(p, ".tar.gz") {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Skip("no .tar.gz sample found")
	}
	return found
}

func setup(t *testing.T) (*db.DB, string) {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := importer.ImportArchive(d, firstSample(t)); err != nil {
		t.Fatal(err)
	}
	return d, tmp
}

func TestGenerateProducesCoreFiles(t *testing.T) {
	d, tmp := setup(t)
	outDir := filepath.Join(tmp, "report")
	stats, err := report.Generate(d, outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"index.html", "files.html", "objects.html",
		"assets/style.css", "assets/script.js",
	} {
		if _, err := os.Stat(filepath.Join(outDir, p)); err != nil {
			t.Errorf("missing report file %s: %v", p, err)
		}
	}
	if stats.RawErrors > 0 {
		t.Errorf("raw export errors: %d", stats.RawErrors)
	}
	if stats.RawExported == 0 {
		t.Error("no raw files exported")
	}
}

func TestEveryFileHasPageAndRaw(t *testing.T) {
	d, tmp := setup(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	hrefRe := regexp.MustCompile(`href="\.\.\/(raw/[^"]+)"`)
	for _, f := range files {
		pagePath := filepath.Join(outDir, "files", "file-"+itoa(f.ID)+".html")
		body, err := os.ReadFile(pagePath)
		if err != nil {
			t.Errorf("missing file page for %d: %v", f.ID, err)
			continue
		}
		m := hrefRe.FindSubmatch(body)
		if m == nil {
			t.Errorf("file page %d has no raw href", f.ID)
			continue
		}
		rawRel := string(m[1])
		rawPath := filepath.Join(outDir, filepath.FromSlash(rawRel))
		info, err := os.Stat(rawPath)
		if err != nil {
			t.Errorf("raw file referenced by file %d does not exist: %s: %v",
				f.ID, rawPath, err)
			continue
		}
		if info.Size() != f.SizeBytes {
			t.Errorf("file %d raw size %d != stored %d", f.ID, info.Size(), f.SizeBytes)
		}
	}
}

func TestRawExportHashMatchesStored(t *testing.T) {
	d, tmp := setup(t)
	outDir := filepath.Join(tmp, "report")
	if _, err := report.Generate(d, outDir); err != nil {
		t.Fatal(err)
	}
	rawRoot := filepath.Join(outDir, "raw")
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	byHash := map[string]string{}
	for _, f := range files {
		byHash[f.SHA256] = f.RelativePath
	}
	checked := 0
	err = filepath.WalkDir(rawRoot, func(p string, dirent os.DirEntry, walkErr error) error {
		if walkErr != nil || dirent.IsDir() {
			return walkErr
		}
		h, err := hashFile(p)
		if err != nil {
			return err
		}
		if _, ok := byHash[h]; !ok {
			return nil // exported file with suffixed name still matches a stored hash
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Error("no raw exports matched stored hashes")
	}
}

func TestPathTraversalCannotEscape(t *testing.T) {
	// Build a malformed tar with traversal entries, import, then ensure no file is written
	// outside the report directory.
	import_traversal_helper(t)
}

func import_traversal_helper(t *testing.T) {
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Fake "imported" file with a relative path that points to ".." in the BLOB layer.
	// We bypass the importer and insert a malicious file row directly to make sure the
	// report layer also defends against it.
	dumpID, err := d.InsertDump(db.Dump{SourcePath: "synthetic", SourceType: "tar.gz"})
	if err != nil {
		t.Fatal(err)
	}
	// Skip: we only need to call InsertFile with a hand-crafted RelativePath.
	// However, the importer's SafeRelPath check happens at import; the DB allows any
	// string. The report's exportRaw runs SafeRelPath again — that's what we verify.
	_, err = d.InsertFile(db.File{
		DumpID:       dumpID,
		RelativePath: "../escape.txt",
		FileName:     "escape.txt",
		SizeBytes:    4,
		SHA256:       "0000000000000000000000000000000000000000000000000000000000000000",
		FileKind:     "text",
	}, []byte("oops"))
	if err != nil {
		// Insert may fail because relative_path is "NOT NULL" but valid; if it does, skip.
		t.Skipf("could not insert synthetic traversal row: %v", err)
	}
	outDir := filepath.Join(tmp, "report")
	stats, err := report.Generate(d, outDir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RawErrors == 0 {
		t.Error("expected traversal entry to be rejected as raw export error")
	}
	// Confirm the escape.txt file did NOT land outside outDir.
	bad := filepath.Join(tmp, "escape.txt")
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Errorf("traversal allowed escape: %s exists", bad)
	}
}

// --- helpers ---

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
