package pxc

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
)

// NodeSummary aggregates per-node milestones and counts derived from events.
type NodeSummary struct {
	Name          string
	FirstSeen     time.Time
	LastSeen      time.Time
	MySQLReady    time.Time
	WSREPReady    time.Time
	SyncedAt      time.Time
	HasMySQLReady bool
	HasWSREP      bool
	HasSynced     bool
	ActedAsDonor  bool
	ActedAsJoiner bool
	HasSST        bool
	HasIST        bool
	Warnings      int
	Errors        int
	Total         int
}

// TimelineBucket is one row in the side-by-side timeline. Events without a
// parseable timestamp are bucketed with the previous bucket's timestamp.
type TimelineBucket struct {
	Timestamp time.Time
	ByNode    map[string][]Event
}

// DumpTimeline is the full PXC analysis for one imported dump.
type DumpTimeline struct {
	DumpID         int64
	Nodes          []string // detected node names, deterministic order
	NodeSummaries  map[string]*NodeSummary
	Buckets        []TimelineBucket
	Events         []Event // sorted chronologically
	Earliest       time.Time
	Latest         time.Time
	HasTime        bool
	WarningCount   int
	ErrorCount     int
	SSTCount       int
	ISTCount       int
	NodesMySQLReady int
	NodesWSREP     int
	ParsePartial   bool // true if some events had no parseable timestamp
}

// AnalysisResult bundles per-dump timelines plus a flat list of log-derived
// findings that callers (e.g. the analyze package) can fold into the existing
// concerns framework.
type AnalysisResult struct {
	Dumps    []DumpTimeline
	Findings []LogFinding
}

// LogFinding is the simplified shape emitted by the PXC log analyzer.
// The analyze package converts it into analyze.Finding for the concerns UI.
type LogFinding struct {
	Severity   string // "info", "warning", "critical"
	Rule       string
	Title      string
	Detail     string
	DumpID     int64
	FileID     int64
	Node       string
	EventType  string
	Timestamp  string // RFC3339 or ""
	LineNumber int
}

// Analyze walks every text-likely file in the database, parses PXC log lines,
// and returns timelines + findings. It is safe to call repeatedly; nothing
// here mutates the database.
func Analyze(d *db.DB) (AnalysisResult, error) {
	files, err := d.ListFiles()
	if err != nil {
		return AnalysisResult{}, err
	}
	dumpsByID := map[int64]*dumpAccum{}

	for _, f := range files {
		// Skip files the importer marked as non-text. The text_content column
		// is the convenience cache; raw bytes remain available either way.
		if !detect.IsText(f.FileKind) {
			continue
		}
		// Prefer in-DB text_content; fall back to raw BLOB so unknown/text
		// kinds we already classified above still yield something to scan.
		content, ok := readText(d, f)
		if !ok || content == "" {
			continue
		}
		if !ContainsPXCMarkers(content) {
			continue
		}
		pathNode, isPXCPath := PXCNodeFromPath(f.RelativePath)
		// Restrict timeline to files that live under a PXC pod directory; that
		// keeps node identity unambiguous (the path name is canonical) and
		// stops haproxy / operator logs from showing up as parallel nodes.
		if !isPXCPath {
			continue
		}
		events := ParseFile(f.DumpID, f.ID, pathNode, content)
		if len(events) == 0 {
			continue
		}
		da := dumpsByID[f.DumpID]
		if da == nil {
			da = &dumpAccum{dumpID: f.DumpID, nodes: map[string]*NodeSummary{}}
			dumpsByID[f.DumpID] = da
		}
		for _, ev := range events {
			da.add(ev)
		}
	}

	res := AnalysisResult{}
	for _, da := range dumpsByID {
		dt := da.build()
		res.Dumps = append(res.Dumps, dt)
		res.Findings = append(res.Findings, deriveFindings(dt)...)
	}
	sort.SliceStable(res.Dumps, func(i, j int) bool {
		return res.Dumps[i].DumpID < res.Dumps[j].DumpID
	})
	return res, nil
}

type dumpAccum struct {
	dumpID int64
	nodes  map[string]*NodeSummary
	events []Event
}

func (a *dumpAccum) add(ev Event) {
	ns := a.nodes[ev.Node]
	if ns == nil {
		ns = &NodeSummary{Name: ev.Node}
		a.nodes[ev.Node] = ns
	}
	ns.Total++
	if ev.HasTime {
		if ns.FirstSeen.IsZero() || ev.Timestamp.Before(ns.FirstSeen) {
			ns.FirstSeen = ev.Timestamp
		}
		if ev.Timestamp.After(ns.LastSeen) {
			ns.LastSeen = ev.Timestamp
		}
	}
	switch ev.Type {
	case MySQLReady, AdminReady:
		if !ns.HasMySQLReady || (ev.HasTime && ev.Timestamp.Before(ns.MySQLReady)) {
			ns.MySQLReady = ev.Timestamp
			ns.HasMySQLReady = true
		}
	case WSREPReady:
		if !ns.HasWSREP || (ev.HasTime && ev.Timestamp.Before(ns.WSREPReady)) {
			ns.WSREPReady = ev.Timestamp
			ns.HasWSREP = true
		}
		ns.HasSynced = true
		if ns.SyncedAt.IsZero() || (ev.HasTime && ev.Timestamp.Before(ns.SyncedAt)) {
			ns.SyncedAt = ev.Timestamp
		}
	case ServerStatusChange:
		if ev.NewState == "donor" {
			ns.ActedAsDonor = true
		}
		if ev.NewState == "joiner" {
			ns.ActedAsJoiner = true
		}
		if ev.NewState == "synced" {
			ns.HasSynced = true
			if ns.SyncedAt.IsZero() {
				ns.SyncedAt = ev.Timestamp
			}
		}
	case SSTStarted, SSTCompleted, SSTSent:
		ns.HasSST = true
	case ISTStarted, ISTRequested, ISTCompleted:
		ns.HasIST = true
	case Warning:
		ns.Warnings++
	case Error:
		ns.Errors++
	}
	a.events = append(a.events, ev)
}

func (a *dumpAccum) build() DumpTimeline {
	dt := DumpTimeline{
		DumpID:        a.dumpID,
		NodeSummaries: a.nodes,
	}
	for name := range a.nodes {
		dt.Nodes = append(dt.Nodes, name)
	}
	sort.Strings(dt.Nodes)

	// Chronological sort with deterministic tie-breakers.
	sort.SliceStable(a.events, func(i, j int) bool {
		ei, ej := a.events[i], a.events[j]
		switch {
		case ei.HasTime && !ej.HasTime:
			return true
		case !ei.HasTime && ej.HasTime:
			return false
		case ei.Timestamp.Equal(ej.Timestamp):
			if ei.FileID != ej.FileID {
				return ei.FileID < ej.FileID
			}
			return ei.LineNumber < ej.LineNumber
		default:
			return ei.Timestamp.Before(ej.Timestamp)
		}
	})
	dt.Events = a.events

	for _, ev := range a.events {
		if !ev.HasTime {
			dt.ParsePartial = true
		} else {
			if !dt.HasTime {
				dt.Earliest = ev.Timestamp
				dt.HasTime = true
			} else if ev.Timestamp.Before(dt.Earliest) {
				dt.Earliest = ev.Timestamp
			}
			if ev.Timestamp.After(dt.Latest) {
				dt.Latest = ev.Timestamp
			}
		}
		switch ev.Type {
		case Warning:
			dt.WarningCount++
		case Error:
			dt.ErrorCount++
		case SSTStarted, SSTCompleted, SSTSent:
			dt.SSTCount++
		case ISTStarted, ISTRequested, ISTCompleted:
			dt.ISTCount++
		}
	}

	for _, ns := range a.nodes {
		if ns.HasMySQLReady {
			dt.NodesMySQLReady++
		}
		if ns.HasWSREP {
			dt.NodesWSREP++
		}
	}

	dt.Buckets = bucketEvents(a.events)
	return dt
}

// bucketEvents groups consecutive events whose timestamps fall in the same
// 1-second window into TimelineBuckets keyed by node. Events without a
// parseable timestamp accumulate under the previous bucket.
func bucketEvents(events []Event) []TimelineBucket {
	const window = time.Second
	if len(events) == 0 {
		return nil
	}
	var out []TimelineBucket
	current := TimelineBucket{ByNode: map[string][]Event{}}
	var bucketTime time.Time
	bucketActive := false

	flush := func() {
		if bucketActive {
			current.Timestamp = bucketTime
			out = append(out, current)
		}
		current = TimelineBucket{ByNode: map[string][]Event{}}
		bucketActive = false
	}

	for _, ev := range events {
		if !bucketActive {
			bucketTime = ev.Timestamp
			bucketActive = true
		} else if ev.HasTime && ev.Timestamp.Sub(bucketTime) >= window {
			flush()
			bucketTime = ev.Timestamp
			bucketActive = true
		}
		current.ByNode[ev.Node] = append(current.ByNode[ev.Node], ev)
	}
	flush()
	return out
}

// deriveFindings turns timeline aggregates into LogFindings consumable by the
// concerns framework. Severity follows the spec table; only one finding per
// (file, type) is emitted to keep the concerns page readable.
func deriveFindings(dt DumpTimeline) []LogFinding {
	var out []LogFinding
	if dt.ParsePartial {
		out = append(out, LogFinding{
			Severity: SevInfo,
			Rule:     "pxc.timeline.parse_partial",
			Title:    fmt.Sprintf("PXC timeline parsing skipped some lines in dump %d", dt.DumpID),
			Detail:   "Some events had no parseable timestamp and inherited the previous timestamp.",
			DumpID:   dt.DumpID,
		})
	}
	if dt.SSTCount > 0 {
		out = append(out, LogFinding{
			Severity: SevInfo,
			Rule:     "pxc.sst.detected",
			Title:    fmt.Sprintf("SST observed (%d events) in dump %d", dt.SSTCount, dt.DumpID),
			Detail:   "State Snapshot Transfer events were detected across PXC nodes.",
			DumpID:   dt.DumpID,
		})
	}
	if dt.ISTCount > 0 {
		out = append(out, LogFinding{
			Severity: SevInfo,
			Rule:     "pxc.ist.detected",
			Title:    fmt.Sprintf("IST observed (%d events) in dump %d", dt.ISTCount, dt.DumpID),
			Detail:   "Incremental State Transfer events were detected across PXC nodes.",
			DumpID:   dt.DumpID,
		})
	}

	// Per-node aggregate findings.
	for _, name := range dt.Nodes {
		ns := dt.NodeSummaries[name]
		if !ns.HasMySQLReady {
			out = append(out, LogFinding{
				Severity: SevWarning,
				Rule:     "pxc.node.not_ready_in_logs",
				Title:    fmt.Sprintf("PXC node %s never reached MySQL-ready in logs", name),
				Detail:   "No 'ready for connections' line was found for this node within the parsed timeline.",
				DumpID:   dt.DumpID,
				Node:     name,
			})
		}
		if !ns.HasWSREP {
			out = append(out, LogFinding{
				Severity: SevWarning,
				Rule:     "pxc.node.never_synced",
				Title:    fmt.Sprintf("PXC node %s never reached WSREP synced in logs", name),
				Detail:   "No 'Synchronized with group' line was found for this node within the parsed timeline.",
				DumpID:   dt.DumpID,
				Node:     name,
			})
		}
	}

	// Per-node first-instance error / warning summaries (limit one per node).
	firstByNode := map[string]bool{}
	for _, ev := range dt.Events {
		switch ev.Type {
		case Error:
			if firstByNode["err|"+ev.Node] {
				continue
			}
			firstByNode["err|"+ev.Node] = true
			out = append(out, LogFinding{
				Severity:   SevCritical,
				Rule:       "pxc.log.error",
				Title:      fmt.Sprintf("Error in %s logs", ev.Node),
				Detail:     ev.Summary,
				DumpID:     ev.DumpID,
				FileID:     ev.FileID,
				Node:       ev.Node,
				EventType:  string(ev.Type),
				Timestamp:  formatTS(ev),
				LineNumber: ev.LineNumber,
			})
		case Warning:
			if firstByNode["warn|"+ev.Node] {
				continue
			}
			firstByNode["warn|"+ev.Node] = true
			out = append(out, LogFinding{
				Severity:   SevWarning,
				Rule:       "pxc.log.warning",
				Title:      fmt.Sprintf("Warning in %s logs", ev.Node),
				Detail:     ev.Summary,
				DumpID:     ev.DumpID,
				FileID:     ev.FileID,
				Node:       ev.Node,
				EventType:  string(ev.Type),
				Timestamp:  formatTS(ev),
				LineNumber: ev.LineNumber,
			})
		}
	}

	return out
}

func formatTS(ev Event) string {
	if !ev.HasTime {
		return ""
	}
	return ev.Timestamp.UTC().Format(time.RFC3339Nano)
}

// readText returns the cached text content; falls back to the raw BLOB only
// when the cache is missing. The BLOB is never mutated.
func readText(d *db.DB, f db.File) (string, bool) {
	if f.TextContent.Valid {
		return f.TextContent.String, true
	}
	raw, err := d.GetRawContent(f.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
		return "", false
	}
	return string(raw), true
}
