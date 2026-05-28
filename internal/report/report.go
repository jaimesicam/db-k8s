// Package report generates a static HTML report and raw-file export from a db-k8s SQLite database.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/db-k8s/db-k8s/internal/analyze"
	"github.com/db-k8s/db-k8s/internal/archive"
	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
)

// Stats summarizes a generated report.
type Stats struct {
	OutputDir   string
	Pages       int
	RawExported int
	RawErrors   int
	Findings    int
	Critical    int
	Warning     int
	Info        int
}

// Generate writes the full report tree to outDir.
// outDir is created if it doesn't exist. Existing files inside outDir may be overwritten.
func Generate(d *db.DB, outDir string) (Stats, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Stats{}, fmt.Errorf("create output dir: %w", err)
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		absOut = outDir
	}

	stats := Stats{OutputDir: absOut}

	if err := writeAssets(absOut); err != nil {
		return stats, err
	}

	dumps, err := d.ListDumps()
	if err != nil {
		return stats, err
	}
	files, err := d.ListFiles()
	if err != nil {
		return stats, err
	}
	yamlDocs, err := d.ListAllYAMLDocs()
	if err != nil {
		return stats, err
	}
	totalFiles, totalBytes, err := d.CountFiles()
	if err != nil {
		return stats, err
	}
	kindCounts, err := d.CountByKind()
	if err != nil {
		return stats, err
	}

	// Export raw bytes first so we can verify hashes and surface raw paths in pages.
	// Process deepest paths first so MkdirAll creates directories before a same-name file
	// (e.g. archives where "foo" is a file AND "foo/bar.txt" exists). Ties break by file ID.
	exportOrder := make([]db.File, len(files))
	copy(exportOrder, files)
	sort.SliceStable(exportOrder, func(i, j int) bool {
		li, lj := len(exportOrder[i].RelativePath), len(exportOrder[j].RelativePath)
		if li != lj {
			return li > lj
		}
		return exportOrder[i].ID < exportOrder[j].ID
	})
	rawPaths := map[int64]string{}
	for _, f := range exportOrder {
		rel, err := exportRaw(d, absOut, f)
		if err != nil {
			stats.RawErrors++
			_ = d.InsertImportError(f.DumpID, f.RelativePath, "raw_export", err.Error())
			continue
		}
		rawPaths[f.ID] = rel
		stats.RawExported++
	}

	// Run analyzer once; results are threaded into every page.
	analysis, err := analyze.Run(d)
	if err != nil {
		return stats, fmt.Errorf("analyze: %w", err)
	}
	sc := analysis.SeverityCounts()
	stats.Findings = len(analysis.Findings)
	stats.Critical = sc[analyze.SeverityCritical]
	stats.Warning = sc[analyze.SeverityWarning]
	stats.Info = sc[analyze.SeverityInfo]

	// Page generation
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	if err := writeIndex(absOut, d, dumps, files, totalFiles, totalBytes, kindCounts, analysis, generatedAt); err != nil {
		return stats, err
	}
	stats.Pages++

	if err := writeFiles(absOut, files, yamlDocs, rawPaths, generatedAt); err != nil {
		return stats, err
	}
	stats.Pages++

	if err := writeObjects(absOut, files, yamlDocs, rawPaths, generatedAt); err != nil {
		return stats, err
	}
	stats.Pages++

	if err := writeConcerns(absOut, analysis, generatedAt); err != nil {
		return stats, err
	}
	stats.Pages++

	for _, dp := range dumps {
		pageCount, err := writeDumpPage(absOut, d, dp, rawPaths, analysis, generatedAt)
		if err != nil {
			return stats, err
		}
		stats.Pages += pageCount
	}

	for _, f := range files {
		if err := writeFilePage(absOut, d, f, rawPaths[f.ID], analysis, generatedAt); err != nil {
			return stats, err
		}
		stats.Pages++
	}

	return stats, nil
}

func writeAssets(outDir string) error {
	assetsDir := filepath.Join(outDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "style.css"), []byte(stylesheet), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(assetsDir, "script.js"), []byte(scriptJS), 0o644)
}

// exportRaw writes a file's BLOB to raw/dump-<id>/<relative_path>.
// Returns the report-relative path (e.g. "raw/dump-1/foo/bar.yaml").
// On collisions (same path used twice, or file-vs-directory conflict from the archive),
// the basename is suffixed with "-id<file-id>" so every file gets a unique deterministic path.
func exportRaw(d *db.DB, outDir string, f db.File) (string, error) {
	safe, ok := archive.SafeRelPath(f.RelativePath)
	if !ok {
		return "", fmt.Errorf("unsafe relative path %q", f.RelativePath)
	}

	rel, dst, err := resolveExportPath(outDir, f.DumpID, f.ID, safe)
	if err != nil {
		return "", err
	}

	raw, err := d.GetRawContent(f.ID)
	if err != nil {
		return "", fmt.Errorf("read blob: %w", err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return "", err
	}

	// Verify exported bytes match the stored SHA256.
	got := sha256.Sum256(raw)
	if want := f.SHA256; want != "" {
		gotHex := hex.EncodeToString(got[:])
		if gotHex != want {
			return "", fmt.Errorf("hash mismatch: have %s, want %s", gotHex, want)
		}
	}
	rh, err := hashFileOnDisk(dst)
	if err != nil {
		return "", err
	}
	if rh != f.SHA256 {
		return "", fmt.Errorf("disk hash mismatch: %s vs %s", rh, f.SHA256)
	}
	return rel, nil
}

// resolveExportPath picks a non-colliding on-disk path under outDir and ensures parent dirs exist.
// It returns the report-relative slash path and the absolute filesystem path.
func resolveExportPath(outDir string, dumpID, fileID int64, safeRel string) (string, string, error) {
	dumpDir := fmt.Sprintf("dump-%d", dumpID)
	outAbs, err := filepath.Abs(outDir)
	if err != nil {
		return "", "", err
	}

	tryWrite := func(rel string) (string, string, bool, error) {
		dst := filepath.Join(outDir, filepath.FromSlash(rel))
		dstAbs, err := filepath.Abs(dst)
		if err != nil {
			return "", "", false, err
		}
		// Guard against escape.
		if !strings.HasPrefix(dstAbs+string(os.PathSeparator), outAbs+string(os.PathSeparator)) &&
			dstAbs != outAbs {
			return "", "", false, fmt.Errorf("path escapes output dir: %s", dstAbs)
		}
		// Refuse to overwrite something already at dst (file or directory).
		if _, statErr := os.Lstat(dst); statErr == nil {
			return "", "", true, nil // collision
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			// MkdirAll fails if any ancestor is a regular file. Signal a collision.
			if isNotADir(err) {
				return "", "", true, nil
			}
			return "", "", false, err
		}
		return rel, dst, false, nil
	}

	natural := filepath.ToSlash(filepath.Join("raw", dumpDir, safeRel))
	rel, dst, collision, err := tryWrite(natural)
	if err != nil {
		return "", "", err
	}
	if !collision {
		return rel, dst, nil
	}

	// Deterministic fallback: suffix the basename with -id<file-id>.
	dir, base := splitSlash(safeRel)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	suffixed := stem + fmt.Sprintf("-id%d", fileID) + ext
	suffixedRel := filepath.ToSlash(filepath.Join("raw", dumpDir, dir, suffixed))
	rel, dst, collision, err = tryWrite(suffixedRel)
	if err != nil {
		return "", "", err
	}
	if collision {
		return "", "", fmt.Errorf("could not resolve path for %q", safeRel)
	}
	return rel, dst, nil
}

func splitSlash(p string) (dir, base string) {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

func isNotADir(err error) bool {
	// ENOTDIR appears as "not a directory" in os.PathError on Linux/macOS.
	return err != nil && strings.Contains(err.Error(), "not a directory")
}

func hashFileOnDisk(p string) (string, error) {
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

type indexDumpRow struct {
	ID         int64
	RootName   string
	SourcePath string
	SourceType string
	ImportedAt string
	FileCount  int64
	Bytes      int64
}

type indexData struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string

	DBPath     string
	TotalDumps int
	TotalFiles int64
	TotalBytes int64
	KindCounts map[string]int64
	Dumps      []indexDumpRow

	Critical    int
	Warning     int
	Info        int
	TopCritical []findingRow
}

func writeIndex(outDir string, d *db.DB, dumps []db.Dump, files []db.File,
	totalFiles, totalBytes int64, kindCounts map[string]int64,
	analysis analyze.Result, generatedAt string) error {
	rows := make([]indexDumpRow, 0, len(dumps))
	for _, dp := range dumps {
		c, b, err := d.DumpFileStats(dp.ID)
		if err != nil {
			return err
		}
		rows = append(rows, indexDumpRow{
			ID: dp.ID, RootName: dp.RootName, SourcePath: dp.SourcePath,
			SourceType: dp.SourceType, ImportedAt: dp.ImportedAt,
			FileCount: c, Bytes: b,
		})
	}
	sc := analysis.SeverityCounts()
	data := indexData{
		Title: "Overview", Nav: "index", AssetBase: "", GeneratedAt: generatedAt,
		DBPath: d.Path(), TotalDumps: len(dumps),
		TotalFiles: totalFiles, TotalBytes: totalBytes,
		KindCounts: ensureAllKinds(kindCounts), Dumps: rows,
		Critical: sc[analyze.SeverityCritical],
		Warning:  sc[analyze.SeverityWarning],
		Info:     sc[analyze.SeverityInfo],
		TopCritical: topFindings(analysis, analyze.SeverityCritical, 5, ""),
	}
	return renderToFile(filepath.Join(outDir, "index.html"), tmplIndex, data)
}

// findingRow is the rendering shape for a finding inside an HTML table.
type findingRow struct {
	Severity    string
	Rule        string
	Title       string
	Detail      string
	Kind        string
	Namespace   string
	Name        string
	DumpID      int64
	FileID      int64
	FileHref    string // relative href to the file detail page (depends on assetBase)
	Prompt      string
	GoogleURL   string
	Search      string
}

func toFindingRow(f analyze.Finding, fileHrefPrefix string) findingRow {
	prompt, gurl := analyze.Investigate(f)
	href := fmt.Sprintf("%sfiles/file-%d.html", fileHrefPrefix, f.FileID)
	return findingRow{
		Severity:  string(f.Severity),
		Rule:      f.Rule,
		Title:     f.Title,
		Detail:    f.Detail,
		Kind:      f.Kind,
		Namespace: f.Namespace,
		Name:      f.Name,
		DumpID:    f.DumpID,
		FileID:    f.FileID,
		FileHref:  href,
		Prompt:    prompt,
		GoogleURL: gurl,
		Search:    strings.ToLower(strings.Join([]string{
			string(f.Severity), f.Rule, f.Title, f.Detail,
			f.Kind, f.Namespace, f.Name,
		}, " ")),
	}
}

// topFindings returns up to n findings of at least minSev (sorted critical first),
// optionally restricted to a single dump.
func topFindings(r analyze.Result, minSev analyze.Severity, n int, hrefPrefix string) []findingRow {
	out := make([]findingRow, 0, n)
	for _, f := range r.Findings {
		if minSev == analyze.SeverityCritical && f.Severity != analyze.SeverityCritical {
			continue
		}
		out = append(out, toFindingRow(f, hrefPrefix))
		if len(out) >= n {
			break
		}
	}
	return out
}

type fileRow struct {
	ID, DumpID int64
	Path       string
	Kind       string
	Size       int64
	SHA256     string
	K8s        string
	RawHref    string
	Search     string
}

type filesPage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string
	Rows        []fileRow
}

func buildFileRows(files []db.File, yamlDocs []db.YAMLDoc, rawPaths map[int64]string) []fileRow {
	yamlByFile := map[int64][]db.YAMLDoc{}
	for _, y := range yamlDocs {
		yamlByFile[y.FileID] = append(yamlByFile[y.FileID], y)
	}
	rows := make([]fileRow, 0, len(files))
	for _, f := range files {
		k8sLabel := ""
		if docs := yamlByFile[f.ID]; len(docs) > 0 {
			first := docs[0]
			if first.Kind != "" || first.Name != "" {
				k8sLabel = strings.TrimSpace(first.Kind + " " + first.Namespace + "/" + first.Name)
				if len(docs) > 1 {
					k8sLabel += fmt.Sprintf(" (+%d)", len(docs)-1)
				}
			}
		}
		search := strings.ToLower(f.RelativePath + " " + f.FileName + " " + f.SHA256 + " " + k8sLabel)
		raw := rawPaths[f.ID]
		if raw == "" {
			raw = fmt.Sprintf("raw/dump-%d/%s", f.DumpID, f.RelativePath)
		}
		rows = append(rows, fileRow{
			ID: f.ID, DumpID: f.DumpID, Path: f.RelativePath,
			Kind: f.FileKind, Size: f.SizeBytes, SHA256: f.SHA256,
			K8s: k8sLabel, RawHref: raw, Search: search,
		})
	}
	return rows
}

func writeFiles(outDir string, files []db.File, yamlDocs []db.YAMLDoc,
	rawPaths map[int64]string, generatedAt string) error {
	rows := buildFileRows(files, yamlDocs, rawPaths)
	data := filesPage{
		Title: "Files", Nav: "files", AssetBase: "", GeneratedAt: generatedAt, Rows: rows,
	}
	return renderToFile(filepath.Join(outDir, "files.html"), tmplFiles, data)
}

type objectRow struct {
	FileID     int64
	Kind       string
	APIVersion string
	Namespace  string
	Name       string
	Path       string
	RawHref    string
	Search     string
}

type objectsPage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string
	Rows        []objectRow
}

func writeObjects(outDir string, files []db.File, yamlDocs []db.YAMLDoc,
	rawPaths map[int64]string, generatedAt string) error {
	fileByID := map[int64]db.File{}
	for _, f := range files {
		fileByID[f.ID] = f
	}
	var rows []objectRow
	for _, y := range yamlDocs {
		f, ok := fileByID[y.FileID]
		if !ok || !y.ParsedOK {
			continue
		}
		if y.Kind == "" && y.Name == "" && y.APIVersion == "" {
			continue
		}
		raw := rawPaths[f.ID]
		if raw == "" {
			raw = fmt.Sprintf("raw/dump-%d/%s", f.DumpID, f.RelativePath)
		}
		search := strings.ToLower(y.Kind + " " + y.APIVersion + " " + y.Namespace + " " +
			y.Name + " " + f.RelativePath)
		rows = append(rows, objectRow{
			FileID: f.ID, Kind: y.Kind, APIVersion: y.APIVersion,
			Namespace: y.Namespace, Name: y.Name, Path: f.RelativePath,
			RawHref: raw, Search: search,
		})
	}
	data := objectsPage{
		Title: "Kubernetes Objects", Nav: "objects", AssetBase: "",
		GeneratedAt: generatedAt, Rows: rows,
	}
	return renderToFile(filepath.Join(outDir, "objects.html"), tmplObjects, data)
}

type dumpPage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string
	Dump        db.Dump
	FileCount   int64
	Bytes       int64
	KindCounts  map[string]int64
	Rows        []fileRow

	Critical int
	Warning  int
	Info     int
	Findings []findingRow
}

func writeDumpPage(outDir string, d *db.DB, dp db.Dump, rawPaths map[int64]string,
	analysis analyze.Result, generatedAt string) (int, error) {
	files, err := d.ListFilesByDump(dp.ID)
	if err != nil {
		return 0, err
	}
	c, b, err := d.DumpFileStats(dp.ID)
	if err != nil {
		return 0, err
	}
	kc, err := d.DumpKindCounts(dp.ID)
	if err != nil {
		return 0, err
	}
	rows := buildFileRows(files, nil, rawPaths)
	sc := analysis.DumpSeverityCounts(dp.ID)
	var findings []findingRow
	for _, f := range analysis.Findings {
		if f.DumpID != dp.ID {
			continue
		}
		findings = append(findings, toFindingRow(f, "../"))
	}
	data := dumpPage{
		Title: fmt.Sprintf("Dump %d", dp.ID), Nav: "index", AssetBase: "../",
		GeneratedAt: generatedAt, Dump: dp, FileCount: c, Bytes: b,
		KindCounts: ensureAllKinds(kc), Rows: rows,
		Critical: sc[analyze.SeverityCritical],
		Warning:  sc[analyze.SeverityWarning],
		Info:     sc[analyze.SeverityInfo],
		Findings: findings,
	}
	dst := filepath.Join(outDir, "dumps", fmt.Sprintf("dump-%d.html", dp.ID))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	if err := renderToFile(dst, tmplDump, data); err != nil {
		return 0, err
	}
	return 1, nil
}

type filePage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string

	File           db.File
	RawHref        string
	YAMLDocs       []db.YAMLDoc
	ShowText       bool
	TextContent    string
	LineCount      int64
	LineCountValid bool

	Summary  string
	Findings []findingRow
}

func writeFilePage(outDir string, d *db.DB, f db.File, rawHref string,
	analysis analyze.Result, generatedAt string) error {
	docs, err := d.ListYAMLDocsByFile(f.ID)
	if err != nil {
		return err
	}
	page := filePage{
		Title: f.FileName, Nav: "files", AssetBase: "../",
		GeneratedAt: generatedAt, File: f,
		RawHref:  rawHref,
		YAMLDocs: docs,
	}
	if f.LineCount.Valid {
		page.LineCount = f.LineCount.Int64
		page.LineCountValid = true
	}
	if detect.IsText(f.FileKind) && f.TextContent.Valid {
		page.ShowText = true
		page.TextContent = f.TextContent.String
	}
	if page.RawHref == "" {
		page.RawHref = fmt.Sprintf("raw/dump-%d/%s", f.DumpID, f.RelativePath)
	}
	page.Summary = analysis.FileSummaries[f.ID]
	for _, finding := range analysis.Findings {
		if finding.FileID == f.ID {
			page.Findings = append(page.Findings, toFindingRow(finding, "../"))
		}
	}
	dst := filepath.Join(outDir, "files", fmt.Sprintf("file-%d.html", f.ID))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return renderToFile(dst, tmplFile, page)
}

type concernsPage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string

	Critical int
	Warning  int
	Info     int
	Findings []findingRow
}

func writeConcerns(outDir string, analysis analyze.Result, generatedAt string) error {
	sc := analysis.SeverityCounts()
	rows := make([]findingRow, 0, len(analysis.Findings))
	for _, f := range analysis.Findings {
		rows = append(rows, toFindingRow(f, ""))
	}
	data := concernsPage{
		Title: "Concerns", Nav: "concerns", AssetBase: "", GeneratedAt: generatedAt,
		Critical: sc[analyze.SeverityCritical],
		Warning:  sc[analyze.SeverityWarning],
		Info:     sc[analyze.SeverityInfo],
		Findings: rows,
	}
	return renderToFile(filepath.Join(outDir, "concerns.html"), tmplConcerns, data)
}

func renderToFile(path string, tmpl interface {
	Execute(w io.Writer, data any) error
}, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

func ensureAllKinds(m map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for _, k := range []string{detect.KindYAML, detect.KindJSON, detect.KindText, detect.KindBinary, detect.KindUnknown} {
		out[k] = 0
	}
	for k, v := range m {
		out[k] = v
	}
	return out
}
