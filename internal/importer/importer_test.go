package importer_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/importer"
)

func samplesDir(t *testing.T) string {
	t.Helper()
	// Find repository root by walking up from this file's package dir until a samples/ exists.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "samples")
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	t.Skip("samples/ not found")
	return ""
}

func collectSamples(t *testing.T) []string {
	dir := samplesDir(t)
	if dir == "" {
		return nil
	}
	var paths []string
	_ = filepath.WalkDir(dir, func(p string, dirent os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if dirent.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".tar.gz") || strings.HasSuffix(p, ".tgz") {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	return paths
}

func TestImportTarGz_AllSamples(t *testing.T) {
	paths := collectSamples(t)
	if len(paths) == 0 {
		t.Skip("no samples found")
	}

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	for _, p := range paths {
		res, err := importer.ImportArchive(d, p)
		if err != nil {
			t.Errorf("import %s: %v", p, err)
			continue
		}
		if res.FilesAdded == 0 {
			t.Errorf("import %s: no files", p)
		}
	}

	dumps, err := d.ListDumps()
	if err != nil {
		t.Fatal(err)
	}
	if len(dumps) != len(paths) {
		t.Errorf("want %d dumps, got %d", len(paths), len(dumps))
	}
}

func TestImportTarGz_BlobHashMatchesRaw(t *testing.T) {
	paths := collectSamples(t)
	if len(paths) == 0 {
		t.Skip("no samples found")
	}
	// Use only the first sample for speed.
	src := paths[0]

	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := importer.ImportArchive(d, src); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Build hash map of original tar entries.
	orig := readTarHashes(t, src)
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, f := range files {
		raw, err := d.GetRawContent(f.ID)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hexSum := hex.EncodeToString(sum[:])
		if hexSum != f.SHA256 {
			t.Errorf("stored SHA256 != recomputed for %q", f.RelativePath)
		}
		if wantHashes, ok := orig[f.RelativePath]; ok {
			found := false
			for _, h := range wantHashes {
				if h == f.SHA256 {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("hash %s for %q not present in original tar (wanted any of %v)",
					f.SHA256, f.RelativePath, wantHashes)
			}
			matched++
		}
	}
	if matched == 0 {
		t.Error("no files matched any original tar entry — relative paths differ")
	}
}

func TestImportDirectory_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	if err := os.MkdirAll(filepath.Join(src, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
	if err := os.WriteFile(filepath.Join(src, "ns", "configmap.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	text := "hello\nworld\n"
	if err := os.WriteFile(filepath.Join(src, "ns", "notes.txt"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	// Empty file
	if err := os.WriteFile(filepath.Join(src, "empty"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	res, err := importer.ImportDirectory(d, src)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesAdded != 3 {
		t.Errorf("want 3 files, got %d", res.FilesAdded)
	}

	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	pathSet := map[string]bool{}
	for _, f := range files {
		pathSet[f.RelativePath] = true
		raw, err := d.GetRawContent(f.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Hash must round-trip.
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("hash mismatch on %s", f.RelativePath)
		}
	}
	root := filepath.Base(src)
	for _, want := range []string{
		root + "/ns/configmap.yaml",
		root + "/ns/notes.txt",
		root + "/empty",
	} {
		if !pathSet[want] {
			t.Errorf("expected file %q not found; got %v", want, keys(pathSet))
		}
	}
}

func TestImportDoesNotNormalize(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	// CRLF + trailing whitespace + no trailing newline — none of these should be touched.
	raw := []byte("line one  \r\nline two\t\r\nline three")
	if err := os.WriteFile(filepath.Join(src, "raw.log"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := importer.ImportDirectory(d, src); err != nil {
		t.Fatal(err)
	}
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 file, got %d", len(files))
	}
	got, err := d.GetRawContent(files[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("raw bytes mutated: got %q want %q", got, raw)
	}
}

func TestImportPathTraversalRejected(t *testing.T) {
	tmp := t.TempDir()
	// Build a tar.gz with one safe entry and one ../escape entry in-memory.
	buf := &bytes.Buffer{}
	gz := gzip.NewWriter(buf)
	tw := tar.NewWriter(gz)
	writeTarFile(t, tw, "ok/safe.txt", "hi")
	writeTarFile(t, tw, "../escape.txt", "nope")
	writeTarFile(t, tw, "/abs.txt", "nope")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(tmp, "bad.tar.gz")
	if err := os.WriteFile(tarPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	res, err := importer.ImportArchive(d, tarPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesAdded != 1 {
		t.Errorf("want exactly 1 safe file imported, got %d", res.FilesAdded)
	}
	if res.Errors < 2 {
		t.Errorf("want >=2 unsafe entries recorded as errors, got %d", res.Errors)
	}
	files, err := d.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.Contains(f.RelativePath, "..") {
			t.Errorf("traversal path stored: %s", f.RelativePath)
		}
	}
}

func TestImportMalformedYAMLContinues(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	// One good YAML, one broken YAML, one plain text — all should land.
	if err := os.WriteFile(filepath.Join(src, "good.yaml"),
		[]byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "bad.yaml"),
		[]byte("apiVersion: v1\nkind: Pod\nmetadata: : : :\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "notes.txt"),
		[]byte("note\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	res, err := importer.ImportDirectory(d, src)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesAdded != 3 {
		t.Errorf("expected 3 files, got %d", res.FilesAdded)
	}
}

func TestImportMultipleDumpsSameDB(t *testing.T) {
	paths := collectSamples(t)
	if len(paths) < 2 {
		t.Skip("need at least 2 samples")
	}
	tmp := t.TempDir()
	d, err := db.Open(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, p := range paths[:2] {
		if _, err := importer.ImportArchive(d, p); err != nil {
			t.Fatal(err)
		}
	}
	dumps, err := d.ListDumps()
	if err != nil {
		t.Fatal(err)
	}
	if len(dumps) != 2 {
		t.Errorf("want 2 dumps, got %d", len(dumps))
	}
	if dumps[0].ID == dumps[1].ID {
		t.Error("dump IDs must be distinct")
	}
}

// --- helpers ---

func writeTarFile(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Size: int64(len(content)), Mode: 0o644,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func readTarHashes(t *testing.T, archivePath string) map[string][]string {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(buf)
		key := strings.TrimPrefix(hdr.Name, "./")
		out[key] = append(out[key], hex.EncodeToString(sum[:]))
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
