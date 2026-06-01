package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/db-k8s/db-k8s/internal/backup"
)

// Per-page view models for backups.html. The Operation struct from
// internal/backup carries everything we need; these wrappers keep template
// rendering trivial and provide pre-built href strings.

type bkSummary struct {
	Total     int
	Succeeded int
	Failed    int
	Running   int
	Pending   int
	Unknown   int
	Warnings  int
	Errors    int
	Backups   int
	Restores  int
	ByEngine  map[backup.Engine]map[backup.Status]int
}

type bkEventRow struct {
	Timestamp  string
	Engine     string
	Namespace  string
	Cluster    string
	OpName     string
	OpKey      string
	Type       string
	Severity   string
	Summary    string
	FileHref   string
	RawHref    string
	LineNumber int
	SearchKey  string
}

type bkOpRow struct {
	OpKey       string
	DumpID      int64
	Engine      string
	Namespace   string
	Cluster     string
	Name        string
	IsRestore   bool
	Type        string
	Storage     string
	Destination string
	Status      string
	Started     string
	Completed   string
	Duration    string
	Warnings    int
	Errors      int
	SourceFiles []bkSourceLink
	SearchKey   string
}

type bkSourceLink struct {
	FileID  int64
	Path    string
	Href    string
	RawHref string
}

type bkEngineSection struct {
	Engine   string
	Title    string
	Ops      []bkOpRow
	Restores []bkOpRow
}

type bkDumpSection struct {
	DumpID    int64
	RootName  string
	Summary   bkSummary
	Engines   []bkEngineSection
	Events    []bkEventRow
	Anchor    string
}

type backupsPage struct {
	Title       string
	Nav         string
	AssetBase   string
	GeneratedAt string

	Summary  bkSummary
	Sections []bkDumpSection
}

// writeBackups renders backups.html. It is always called so the nav link
// resolves; an empty Sections list produces an empty-state notice in the
// template.
func writeBackups(outDir string, bk backup.AnalysisResult, dumpRoot map[int64]string,
	rawPaths map[int64]string, fileRel map[int64]string, generatedAt string) error {
	data := backupsPage{
		Title:       "Backups",
		Nav:         "backups",
		AssetBase:   "",
		GeneratedAt: generatedAt,
		Sections:    buildBackupSections(bk, dumpRoot, rawPaths, fileRel),
	}
	data.Summary = aggregateSummary(data.Sections)
	return renderToFile(filepath.Join(outDir, "backups.html"), tmplBackups, data)
}

func aggregateSummary(sections []bkDumpSection) bkSummary {
	out := bkSummary{ByEngine: map[backup.Engine]map[backup.Status]int{}}
	for _, s := range sections {
		out.Total += s.Summary.Total
		out.Succeeded += s.Summary.Succeeded
		out.Failed += s.Summary.Failed
		out.Running += s.Summary.Running
		out.Pending += s.Summary.Pending
		out.Unknown += s.Summary.Unknown
		out.Warnings += s.Summary.Warnings
		out.Errors += s.Summary.Errors
		out.Backups += s.Summary.Backups
		out.Restores += s.Summary.Restores
		for engine, m := range s.Summary.ByEngine {
			if out.ByEngine[engine] == nil {
				out.ByEngine[engine] = map[backup.Status]int{}
			}
			for st, c := range m {
				out.ByEngine[engine][st] += c
			}
		}
	}
	return out
}

func buildBackupSections(bk backup.AnalysisResult, dumpRoot map[int64]string,
	rawPaths map[int64]string, fileRel map[int64]string) []bkDumpSection {
	byDump := map[int64][]backup.Operation{}
	var dumpIDs []int64
	for _, op := range bk.Operations {
		if _, seen := byDump[op.DumpID]; !seen {
			dumpIDs = append(dumpIDs, op.DumpID)
		}
		byDump[op.DumpID] = append(byDump[op.DumpID], op)
	}
	sort.Slice(dumpIDs, func(i, j int) bool { return dumpIDs[i] < dumpIDs[j] })
	out := make([]bkDumpSection, 0, len(dumpIDs))
	for _, id := range dumpIDs {
		section := bkDumpSection{
			DumpID:   id,
			RootName: dumpRoot[id],
			Anchor:   fmt.Sprintf("bk-dump-%d", id),
			Summary:  bkSummary{ByEngine: map[backup.Engine]map[backup.Status]int{}},
		}
		engineBuckets := map[backup.Engine]*bkEngineSection{}
		for _, op := range byDump[id] {
			section.Summary.Total++
			switch op.Status {
			case backup.StatusSucceeded:
				section.Summary.Succeeded++
			case backup.StatusFailed:
				section.Summary.Failed++
			case backup.StatusRunning:
				section.Summary.Running++
			case backup.StatusPending:
				section.Summary.Pending++
			default:
				section.Summary.Unknown++
			}
			section.Summary.Warnings += op.Warnings
			section.Summary.Errors += op.Errors
			if op.IsRestore {
				section.Summary.Restores++
			} else {
				section.Summary.Backups++
			}
			if section.Summary.ByEngine[op.Engine] == nil {
				section.Summary.ByEngine[op.Engine] = map[backup.Status]int{}
			}
			section.Summary.ByEngine[op.Engine][op.Status]++

			sec, ok := engineBuckets[op.Engine]
			if !ok {
				sec = &bkEngineSection{
					Engine: string(op.Engine),
					Title:  engineTitle(op.Engine),
				}
				engineBuckets[op.Engine] = sec
			}
			row := toBkOpRow(op, rawPaths, fileRel)
			if op.IsRestore {
				sec.Restores = append(sec.Restores, row)
			} else {
				sec.Ops = append(sec.Ops, row)
			}
			// Per-event rows for the combined timeline.
			for _, ev := range op.Events {
				section.Events = append(section.Events, toBkEventRow(op, ev, rawPaths, fileRel))
			}
		}
		// Engine display order: pxc, postgres, mongodb, everest, unknown.
		for _, e := range []backup.Engine{backup.EnginePXC, backup.EnginePostgres,
			backup.EngineMongoDB, backup.EngineEverest, backup.EngineUnknown} {
			if sec, ok := engineBuckets[e]; ok {
				section.Engines = append(section.Engines, *sec)
			}
		}
		sort.SliceStable(section.Events, func(i, j int) bool {
			return section.Events[i].Timestamp < section.Events[j].Timestamp
		})
		out = append(out, section)
	}
	return out
}

func toBkOpRow(op backup.Operation, rawPaths, fileRel map[int64]string) bkOpRow {
	var sources []bkSourceLink
	var ids []int64
	for id := range op.SourceFiles {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		raw := rawPaths[id]
		if raw == "" {
			raw = fmt.Sprintf("raw/dump-%d/%s", op.DumpID, fileRel[id])
		}
		sources = append(sources, bkSourceLink{
			FileID:  id,
			Path:    fileRel[id],
			Href:    fmt.Sprintf("files/file-%d.html", id),
			RawHref: raw,
		})
	}
	row := bkOpRow{
		OpKey:       op.Key,
		DumpID:      op.DumpID,
		Engine:      string(op.Engine),
		Namespace:   op.Namespace,
		Cluster:     op.Cluster,
		Name:        op.Name,
		IsRestore:   op.IsRestore,
		Type:        op.Type,
		Storage:     op.Storage,
		Destination: op.Destination,
		Status:      string(op.Status),
		Started:     formatBkTime(op.Started, op.HasStart),
		Completed:   formatBkTime(op.Completed, op.HasFinish),
		Duration:    op.Duration(),
		Warnings:    op.Warnings,
		Errors:      op.Errors,
		SourceFiles: sources,
	}
	row.SearchKey = strings.ToLower(strings.Join([]string{
		row.Engine, row.Namespace, row.Cluster, row.Name, row.Status,
		row.Storage, row.Destination,
	}, " "))
	return row
}

func toBkEventRow(op backup.Operation, ev backup.Event, rawPaths, fileRel map[int64]string) bkEventRow {
	raw := rawPaths[ev.FileID]
	if raw == "" {
		raw = fmt.Sprintf("raw/dump-%d/%s", op.DumpID, fileRel[ev.FileID])
	}
	fileHref := fmt.Sprintf("files/file-%d.html", ev.FileID)
	if ev.LineNumber > 0 {
		fileHref = fmt.Sprintf("files/file-%d.html#line-%d", ev.FileID, ev.LineNumber)
	}
	row := bkEventRow{
		Timestamp:  formatBkTime(ev.Timestamp, ev.HasTime),
		Engine:     string(op.Engine),
		Namespace:  op.Namespace,
		Cluster:    op.Cluster,
		OpName:     op.Name,
		OpKey:      op.Key,
		Type:       string(ev.Type),
		Severity:   ev.Severity,
		Summary:    ev.Summary,
		FileHref:   fileHref,
		RawHref:    raw,
		LineNumber: ev.LineNumber,
	}
	row.SearchKey = strings.ToLower(strings.Join([]string{
		row.Engine, row.Namespace, row.OpName, row.Type, row.Severity, row.Summary,
	}, " "))
	return row
}

func engineTitle(e backup.Engine) string {
	switch e {
	case backup.EnginePXC:
		return "PXC Backups"
	case backup.EnginePostgres:
		return "PostgreSQL Backups"
	case backup.EngineMongoDB:
		return "MongoDB Backups"
	case backup.EngineEverest:
		return "Everest Backup Objects"
	}
	return "Other Backups"
}

func formatBkTime(t time.Time, has bool) string {
	if !has || t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

// fileBackupContributions returns the bkContribRow list for one file — the
// reverse mapping consumed by the file detail page.
func fileBackupContributions(fileID int64, bk backup.AnalysisResult) []bkContribRow {
	var out []bkContribRow
	for _, op := range bk.Operations {
		if !op.SourceFiles[fileID] {
			continue
		}
		var types []string
		typeSeen := map[string]bool{}
		for _, ev := range op.Events {
			if ev.FileID != fileID {
				continue
			}
			if !typeSeen[string(ev.Type)] {
				typeSeen[string(ev.Type)] = true
				types = append(types, string(ev.Type))
			}
		}
		when := ""
		if op.HasFinish {
			when = op.Completed.UTC().Format("2006-01-02 15:04:05")
		} else if op.HasStart {
			when = op.Started.UTC().Format("2006-01-02 15:04:05")
		}
		out = append(out, bkContribRow{
			OpKey:     op.Key,
			Engine:    string(op.Engine),
			Namespace: op.Namespace,
			Name:      op.Name,
			Status:    string(op.Status),
			EventList: strings.Join(types, ", "),
			When:      when,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type bkContribRow struct {
	OpKey     string
	Engine    string
	Namespace string
	Name      string
	Status    string
	EventList string
	When      string
}
