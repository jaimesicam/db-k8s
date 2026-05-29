package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/db-k8s/db-k8s/internal/pxc"
)

// PXC timeline rendering. The page is a combined index: one section per dump
// that contains any classified PXC log events. Empty dumps are simply omitted
// (and a "no events" notice is rendered when nothing was found at all).

type timelineEventCell struct {
	EventType  string
	Severity   string
	Summary    string
	Component  string
	Timestamp  string
	Node       string
	FileHref   string
	RawHref    string
	LineNumber int
	Raw        string
	OldState   string
	NewState   string
	// SearchKey is a lowercase concatenation used by the client-side filter.
	SearchKey string
}

type timelineBucketRow struct {
	Timestamp string
	// Cells holds one entry per node column in node order.
	Cells [][]timelineEventCell
}

type timelineNodeCard struct {
	Name          string
	FirstSeen     string
	LastSeen      string
	MySQLReady    string
	WSREPReady    string
	SyncedAt      string
	ActedAsDonor  bool
	ActedAsJoiner bool
	HasSST        bool
	HasIST        bool
	Warnings      int
	Errors        int
	Total         int
}

type timelineDumpSection struct {
	DumpID          int64
	RootName        string
	Nodes           []string
	NodeCards       []timelineNodeCard
	Buckets         []timelineBucketRow
	Earliest        string
	Latest          string
	Total           int
	Warnings        int
	Errors          int
	SSTCount        int
	ISTCount        int
	NodesMySQLReady int
	NodesWSREP      int
	ParsePartial    bool
}

type timelinePage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string

	Sections []timelineDumpSection
}

func writeTimeline(outDir string, pxcRes pxc.AnalysisResult, dumpRoot map[int64]string,
	rawPaths map[int64]string, fileRel map[int64]string, generatedAt string) error {
	sections := buildTimelineSections(pxcRes, dumpRoot, rawPaths, fileRel)
	data := timelinePage{
		Title:       "PXC Timeline",
		Nav:         "timeline",
		AssetBase:   "",
		GeneratedAt: generatedAt,
		Sections:    sections,
	}
	return renderToFile(filepath.Join(outDir, "pxc-timeline.html"), tmplTimeline, data)
}

func buildTimelineSections(pxcRes pxc.AnalysisResult, dumpRoot map[int64]string,
	rawPaths map[int64]string, fileRel map[int64]string) []timelineDumpSection {
	out := make([]timelineDumpSection, 0, len(pxcRes.Dumps))
	for _, dt := range pxcRes.Dumps {
		if len(dt.Events) == 0 {
			continue
		}
		nodes := append([]string{}, dt.Nodes...)
		sort.Strings(nodes)
		section := timelineDumpSection{
			DumpID:          dt.DumpID,
			RootName:        dumpRoot[dt.DumpID],
			Nodes:           nodes,
			Earliest:        formatTime(dt.Earliest, dt.HasTime),
			Latest:          formatTime(dt.Latest, dt.HasTime),
			Total:           len(dt.Events),
			Warnings:        dt.WarningCount,
			Errors:          dt.ErrorCount,
			SSTCount:        dt.SSTCount,
			ISTCount:        dt.ISTCount,
			NodesMySQLReady: dt.NodesMySQLReady,
			NodesWSREP:      dt.NodesWSREP,
			ParsePartial:    dt.ParsePartial,
		}
		for _, n := range nodes {
			ns := dt.NodeSummaries[n]
			section.NodeCards = append(section.NodeCards, timelineNodeCard{
				Name:          ns.Name,
				FirstSeen:     formatTime(ns.FirstSeen, !ns.FirstSeen.IsZero()),
				LastSeen:      formatTime(ns.LastSeen, !ns.LastSeen.IsZero()),
				MySQLReady:    formatTime(ns.MySQLReady, ns.HasMySQLReady),
				WSREPReady:    formatTime(ns.WSREPReady, ns.HasWSREP),
				SyncedAt:      formatTime(ns.SyncedAt, ns.HasSynced),
				ActedAsDonor:  ns.ActedAsDonor,
				ActedAsJoiner: ns.ActedAsJoiner,
				HasSST:        ns.HasSST,
				HasIST:        ns.HasIST,
				Warnings:      ns.Warnings,
				Errors:        ns.Errors,
				Total:         ns.Total,
			})
		}
		nodeIndex := map[string]int{}
		for i, n := range nodes {
			nodeIndex[n] = i
		}
		for _, b := range dt.Buckets {
			row := timelineBucketRow{
				Timestamp: formatTime(b.Timestamp, !b.Timestamp.IsZero()),
				Cells:     make([][]timelineEventCell, len(nodes)),
			}
			for nodeName, evs := range b.ByNode {
				idx, ok := nodeIndex[nodeName]
				if !ok {
					continue
				}
				for _, ev := range evs {
					row.Cells[idx] = append(row.Cells[idx], buildEventCell(ev, rawPaths, fileRel))
				}
			}
			section.Buckets = append(section.Buckets, row)
		}
		out = append(out, section)
	}
	return out
}

func buildEventCell(ev pxc.Event, rawPaths map[int64]string, fileRel map[int64]string) timelineEventCell {
	rel := fileRel[ev.FileID]
	if rel == "" {
		rel = ""
	}
	cell := timelineEventCell{
		EventType:  string(ev.Type),
		Severity:   ev.Severity,
		Summary:    ev.Summary,
		Component:  ev.Component,
		Timestamp:  formatTime(ev.Timestamp, ev.HasTime),
		Node:       ev.Node,
		FileHref:   fmt.Sprintf("files/file-%d.html#line-%d", ev.FileID, ev.LineNumber),
		RawHref:    rawPaths[ev.FileID],
		LineNumber: ev.LineNumber,
		Raw:        ev.Raw,
		OldState:   ev.OldState,
		NewState:   ev.NewState,
	}
	cell.SearchKey = strings.ToLower(strings.Join([]string{
		string(ev.Type), ev.Severity, ev.Node, ev.Summary, ev.Component, ev.Raw,
	}, " "))
	if cell.RawHref == "" {
		cell.RawHref = fmt.Sprintf("raw/dump-%d/%s", ev.DumpID, rel)
	}
	return cell
}

func formatTime(t time.Time, has bool) string {
	if !has || t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05.000")
}
