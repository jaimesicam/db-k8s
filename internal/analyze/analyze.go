// Package analyze inspects imported YAML files and produces per-file summaries
// plus a list of findings (concerns) using a rule-based diagnostic layer.
//
// Analysis runs at report generation time. It never modifies the canonical BLOB
// stored in SQLite — everything here is derived.
package analyze

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
)

// Severity ranks how urgently a finding deserves attention.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// severityRank gives a deterministic sort order: critical first.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Finding is one concern surfaced by a rule.
type Finding struct {
	Severity Severity
	Rule     string
	Title    string
	Detail   string
	// Context attached to the source object.
	DumpID     int64
	FileID     int64
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	// Fields used by the Investigate panel — curated, never raw BLOB content.
	Fields map[string]string
}

// Summary is a one-line description of a YAML file's contents.
type Summary struct {
	FileID int64
	Line   string
}

// Result is the output of Run.
type Result struct {
	FileSummaries map[int64]string // file_id -> summary line
	Findings      []Finding        // global list, deterministically ordered
}

// FindingsByFile groups findings by file_id for per-file rendering.
func (r Result) FindingsByFile() map[int64][]Finding {
	out := map[int64][]Finding{}
	for _, f := range r.Findings {
		out[f.FileID] = append(out[f.FileID], f)
	}
	return out
}

// FindingsByDump groups findings by dump_id.
func (r Result) FindingsByDump() map[int64][]Finding {
	out := map[int64][]Finding{}
	for _, f := range r.Findings {
		out[f.DumpID] = append(out[f.DumpID], f)
	}
	return out
}

// SeverityCounts returns counts across the whole result.
func (r Result) SeverityCounts() map[Severity]int {
	out := map[Severity]int{SeverityCritical: 0, SeverityWarning: 0, SeverityInfo: 0}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// DumpSeverityCounts returns severity counts for a specific dump.
func (r Result) DumpSeverityCounts(dumpID int64) map[Severity]int {
	out := map[Severity]int{SeverityCritical: 0, SeverityWarning: 0, SeverityInfo: 0}
	for _, f := range r.Findings {
		if f.DumpID == dumpID {
			out[f.Severity]++
		}
	}
	return out
}

// Run analyzes every YAML file in the database and returns per-file summaries
// plus a deterministically ordered list of findings.
func Run(d *db.DB) (Result, error) {
	files, err := d.ListFiles()
	if err != nil {
		return Result{}, err
	}
	res := Result{FileSummaries: map[int64]string{}}
	for _, f := range files {
		if f.FileKind != detect.KindYAML {
			continue
		}
		raw, err := d.GetRawContent(f.ID)
		if err != nil {
			continue
		}
		summary, findings := analyzeFile(f, raw)
		if summary != "" {
			res.FileSummaries[f.ID] = summary
		}
		res.Findings = append(res.Findings, findings...)
	}
	sortFindings(res.Findings)
	return res, nil
}

// analyzeFile is the per-file pipeline: decode every YAML document, flatten Lists,
// build the summary string, and dispatch each object to its rules.
func analyzeFile(f db.File, raw []byte) (string, []Finding) {
	docs := decodeAllDocs(raw)
	// Flatten Lists into their items so a pods.yaml becomes 42 Pod docs.
	flat := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		flat = append(flat, flattenList(d)...)
	}
	summary := buildSummary(flat)

	var findings []Finding
	for _, doc := range flat {
		findings = append(findings, dispatch(f, doc)...)
	}
	// Event aggregation: collapse many event.warning findings to one per (kind, reason).
	findings = aggregateEvents(findings)
	return summary, findings
}

// decodeAllDocs returns every YAML document in the stream as a generic map.
// Malformed documents are skipped — by the time we get here, the importer already
// recorded any parse error in yaml_documents.
func decodeAllDocs(raw []byte) []map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var out []map[string]any
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out
}

// flattenList returns items from a v1.List, or the original doc wrapped in a slice.
func flattenList(doc map[string]any) []map[string]any {
	if str(doc, "kind") != "List" {
		return []map[string]any{doc}
	}
	items, _ := doc["items"].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// buildSummary produces a one-line description of a file's contents.
// Examples:
//   "42 Pods (35 Running, 3 Failed, 4 Pending)"
//   "176 Events (151 Normal, 25 Warning)"
//   "2 PerconaXtraDBCluster (1 ready, 1 initializing)"
func buildSummary(docs []map[string]any) string {
	if len(docs) == 0 {
		return ""
	}
	byKind := map[string][]map[string]any{}
	var order []string
	for _, d := range docs {
		k := str(d, "kind")
		if k == "" {
			k = "(unknown)"
		}
		if _, seen := byKind[k]; !seen {
			order = append(order, k)
		}
		byKind[k] = append(byKind[k], d)
	}
	sort.Strings(order)

	var parts []string
	for _, k := range order {
		docs := byKind[k]
		parts = append(parts, summarizeKind(k, docs))
	}
	return strings.Join(parts, "; ")
}

func summarizeKind(kind string, docs []map[string]any) string {
	n := len(docs)
	switch kind {
	case "Pod":
		phases := map[string]int{}
		for _, d := range docs {
			phases[str(d, "status", "phase")]++
		}
		return fmt.Sprintf("%d Pod%s (%s)", n, plural(n), formatCounts(phases))
	case "Event":
		types := map[string]int{}
		for _, d := range docs {
			types[str(d, "type")]++
		}
		return fmt.Sprintf("%d Event%s (%s)", n, plural(n), formatCounts(types))
	case "PerconaXtraDBCluster", "PerconaServerMongoDB", "PerconaPGCluster":
		states := map[string]int{}
		for _, d := range docs {
			states[str(d, "status", "state")]++
		}
		return fmt.Sprintf("%d %s (%s)", n, kind, formatCounts(states))
	case "Node":
		notReady := 0
		for _, d := range docs {
			if !nodeIsReady(d) {
				notReady++
			}
		}
		if notReady > 0 {
			return fmt.Sprintf("%d Nodes (%d NotReady)", n, notReady)
		}
		return fmt.Sprintf("%d Nodes (all Ready)", n)
	case "PersistentVolumeClaim":
		phases := map[string]int{}
		for _, d := range docs {
			phases[str(d, "status", "phase")]++
		}
		return fmt.Sprintf("%d PVC%s (%s)", n, plural(n), formatCounts(phases))
	}
	return fmt.Sprintf("%d %s%s", n, kind, plural(n))
}

func formatCounts(m map[string]int) string {
	if len(m) == 0 {
		return "no status"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			k = "(none)"
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		realKey := k
		if k == "(none)" {
			realKey = ""
		}
		parts = append(parts, fmt.Sprintf("%d %s", m[realKey], k))
	}
	return strings.Join(parts, ", ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// sortFindings imposes the canonical order: critical first, then by namespace, kind, name, rule.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := severityRank(fs[i].Severity), severityRank(fs[j].Severity); a != b {
			return a < b
		}
		if a, b := fs[i].Namespace, fs[j].Namespace; a != b {
			return a < b
		}
		if a, b := fs[i].Kind, fs[j].Kind; a != b {
			return a < b
		}
		if a, b := fs[i].Name, fs[j].Name; a != b {
			return a < b
		}
		return fs[i].Rule < fs[j].Rule
	})
}
