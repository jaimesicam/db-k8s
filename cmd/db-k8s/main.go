// Command db-k8s imports Kubernetes debug dumps into SQLite and renders a static HTML report.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/db-k8s/db-k8s/internal/analyze"
	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
	"github.com/db-k8s/db-k8s/internal/importer"
	"github.com/db-k8s/db-k8s/internal/report"
)

const defaultDBPath = "db-k8s.db"
const defaultReportDir = "./db-k8s-report"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Parse global flags until the first non-flag, which is the subcommand.
	global := flag.NewFlagSet("db-k8s", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	dbPath := global.String("db", defaultDBPath, "path to SQLite database file")
	global.Usage = func() {
		fmt.Fprintln(os.Stderr, usageText)
	}
	if err := global.Parse(args); err != nil {
		return err
	}

	rest := global.Args()
	if len(rest) == 0 {
		global.Usage()
		return errors.New("missing command")
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "import":
		return cmdImport(*dbPath, cmdArgs)
	case "report":
		return cmdReport(*dbPath, cmdArgs)
	case "list-dumps":
		return cmdListDumps(*dbPath, cmdArgs)
	case "list-files":
		return cmdListFiles(*dbPath, cmdArgs)
	case "show-file":
		return cmdShowFile(*dbPath, cmdArgs)
	case "concerns":
		return cmdConcerns(*dbPath, cmdArgs)
	case "help", "-h", "--help":
		fmt.Println(usageText)
		return nil
	default:
		global.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

const usageText = `db-k8s — Kubernetes debug-dump importer and report generator

Usage:
  db-k8s [--db PATH] <command> [arguments]

Commands:
  import <path>                   Import a .tar.gz archive or extracted directory
  report [--output DIR]           Generate the static HTML report (default ./db-k8s-report)
  list-dumps                      List dumps in the database
  list-files                      List imported files
  show-file <file-id>             Show file metadata (and text content if safe)
  concerns [--severity SEV]       List analyzer findings (critical|warning|info)
           [--dump N]
  help                            Show this help

Global flags:
  --db PATH                       SQLite database path (default db-k8s.db)`

func openDB(path string) (*db.DB, error) {
	return db.Open(path)
}

func cmdImport(dbPath string, args []string) error {
	if len(args) < 1 {
		return errors.New("import: missing source path")
	}
	src := args[0]
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	res, err := importer.Import(d, src)
	if err != nil {
		return err
	}
	fmt.Printf("Imported %q as dump #%d: %d files, %d bytes, %d errors\n",
		src, res.DumpID, res.FilesAdded, res.BytesAdded, res.Errors)
	return nil
}

func cmdReport(dbPath string, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	out := fs.String("output", defaultReportDir, "output directory for the report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	stats, err := report.Generate(d, *out)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote report to %s\n", stats.OutputDir)
	fmt.Printf("  pages: %d\n  raw files exported: %d (%d errors)\n",
		stats.Pages, stats.RawExported, stats.RawErrors)
	fmt.Printf("  concerns: %d (%d critical, %d warning, %d info)\n",
		stats.Findings, stats.Critical, stats.Warning, stats.Info)
	return nil
}

func cmdListDumps(dbPath string, _ []string) error {
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	dumps, err := d.ListDumps()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tROOT\tTYPE\tIMPORTED\tFILES\tBYTES\tSOURCE")
	for _, dp := range dumps {
		c, b, err := d.DumpFileStats(dp.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n",
			dp.ID, dp.RootName, dp.SourceType, dp.ImportedAt, c, b, dp.SourcePath)
	}
	return w.Flush()
}

func cmdListFiles(dbPath string, _ []string) error {
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	files, err := d.ListFiles()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tDUMP\tKIND\tSIZE\tSHA256\tPATH")
	for _, f := range files {
		shortHash := f.SHA256
		if len(shortHash) > 12 {
			shortHash = shortHash[:12]
		}
		fmt.Fprintf(w, "%d\t%d\t%s\t%d\t%s\t%s\n",
			f.ID, f.DumpID, f.FileKind, f.SizeBytes, shortHash, f.RelativePath)
	}
	return w.Flush()
}

func cmdShowFile(dbPath string, args []string) error {
	if len(args) < 1 {
		return errors.New("show-file: missing file-id")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("show-file: invalid file-id %q: %w", args[0], err)
	}
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	f, err := d.GetFile(id)
	if err != nil {
		return fmt.Errorf("get file %d: %w", id, err)
	}
	docs, err := d.ListYAMLDocsByFile(id)
	if err != nil {
		return err
	}
	fmt.Printf("File ID:        %d\n", f.ID)
	fmt.Printf("Dump ID:        %d\n", f.DumpID)
	fmt.Printf("Relative path:  %s\n", f.RelativePath)
	fmt.Printf("File name:      %s\n", f.FileName)
	fmt.Printf("Size:           %d bytes\n", f.SizeBytes)
	fmt.Printf("SHA256:         %s\n", f.SHA256)
	fmt.Printf("Kind:           %s\n", f.FileKind)
	if f.ContentType != "" {
		fmt.Printf("Content-Type:   %s\n", f.ContentType)
	}
	if f.ModifiedTime != "" {
		fmt.Printf("Modified:       %s\n", f.ModifiedTime)
	}
	if f.FileMode != "" {
		fmt.Printf("Mode:           %s\n", f.FileMode)
	}
	if f.LineCount.Valid {
		fmt.Printf("Lines:          %d\n", f.LineCount.Int64)
	}
	for _, y := range docs {
		if !y.ParsedOK {
			fmt.Printf("k8s document:   parse error: %s\n", y.ParseError)
			continue
		}
		if y.Kind == "" && y.Name == "" && y.APIVersion == "" {
			continue
		}
		fmt.Printf("k8s document:   %s %s/%s (%s)\n",
			y.Kind, y.Namespace, y.Name, y.APIVersion)
	}
	// Analyzer summary + findings for this file (if YAML).
	if f.FileKind == detect.KindYAML {
		analysis, err := analyze.Run(d)
		if err == nil {
			if s, ok := analysis.FileSummaries[id]; ok && s != "" {
				fmt.Printf("Summary:        %s\n", s)
			}
			for _, fi := range analysis.Findings {
				if fi.FileID == id {
					fmt.Printf("Concern:        [%s] %s — %s\n",
						fi.Severity, fi.Rule, fi.Title)
				}
			}
		}
	}
	if detect.IsText(f.FileKind) && f.TextContent.Valid {
		fmt.Println("---")
		fmt.Print(f.TextContent.String)
		if len(f.TextContent.String) > 0 &&
			f.TextContent.String[len(f.TextContent.String)-1] != '\n' {
			fmt.Println()
		}
	} else {
		fmt.Println("---")
		fmt.Printf("(content is %s — use the report's raw file link to access bytes)\n", f.FileKind)
	}
	return nil
}

func cmdConcerns(dbPath string, args []string) error {
	fs := flag.NewFlagSet("concerns", flag.ContinueOnError)
	sev := fs.String("severity", "", "minimum severity: critical | warning | info")
	dumpID := fs.Int64("dump", 0, "restrict to a single dump ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := openDB(dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	result, err := analyze.Run(d)
	if err != nil {
		return err
	}
	minRank := -1
	switch *sev {
	case "critical":
		minRank = 0
	case "warning":
		minRank = 1
	case "info":
		minRank = 2
	case "":
		minRank = 2
	default:
		return fmt.Errorf("concerns: invalid --severity %q (want critical|warning|info)", *sev)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tDUMP\tRULE\tNAMESPACE/NAME\tTITLE")
	shown := 0
	for _, fi := range result.Findings {
		r := severityCLIRank(fi.Severity)
		if r > minRank {
			continue
		}
		if *dumpID > 0 && fi.DumpID != *dumpID {
			continue
		}
		shown++
		fmt.Fprintf(w, "%s\t%d\t%s\t%s/%s\t%s\n",
			fi.Severity, fi.DumpID, fi.Rule, fi.Namespace, fi.Name, fi.Title)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	sc := result.SeverityCounts()
	fmt.Printf("\n%d shown — totals: %d critical, %d warning, %d info\n",
		shown, sc[analyze.SeverityCritical], sc[analyze.SeverityWarning], sc[analyze.SeverityInfo])
	return nil
}

func severityCLIRank(s analyze.Severity) int {
	switch s {
	case analyze.SeverityCritical:
		return 0
	case analyze.SeverityWarning:
		return 1
	}
	return 2
}
