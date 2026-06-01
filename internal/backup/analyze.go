package backup

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
)

// AnalysisResult bundles the per-dump operation set plus a flat list of
// log-derived findings for the existing concerns framework.
type AnalysisResult struct {
	Operations []Operation
	Findings   []LogFinding
}

// LogFinding mirrors the pxc.LogFinding shape so analyze can fold both into
// the existing Finding pipeline uniformly.
type LogFinding struct {
	Severity   string
	Rule       string
	Title      string
	Detail     string
	DumpID     int64
	FileID     int64
	Engine     string
	Namespace  string
	Cluster    string
	Name       string
	Status     string
	Started    string
	Completed  string
	Storage    string
	Dest       string
	OpKey      string
	LineNumber int
}

// CountByEngineStatus returns counts of ops grouped by engine and status,
// useful for the index summary.
func (r AnalysisResult) CountByEngineStatus() map[Engine]map[Status]int {
	out := map[Engine]map[Status]int{}
	for _, op := range r.Operations {
		if _, ok := out[op.Engine]; !ok {
			out[op.Engine] = map[Status]int{}
		}
		out[op.Engine][op.Status]++
	}
	return out
}

// Analyze walks every file in d, builds Operations from backup/restore CRDs,
// Jobs, Pods, and Events, mines backup pod logs for evidence, and emits
// findings. It performs three passes over the file set, all read-only.
func Analyze(d *db.DB) (AnalysisResult, error) {
	files, err := d.ListFiles()
	if err != nil {
		return AnalysisResult{}, err
	}
	ops := map[string]*Operation{}

	// Pass 1: backup/restore CRDs → Operations
	for _, f := range files {
		if f.FileKind != detect.KindYAML {
			continue
		}
		raw, err := d.GetRawContent(f.ID)
		if err != nil {
			continue
		}
		ingestCRDs(ops, f, raw)
	}

	// Pass 2: Jobs / Pods / Events → attach evidence
	for _, f := range files {
		if f.FileKind != detect.KindYAML {
			continue
		}
		raw, err := d.GetRawContent(f.ID)
		if err != nil {
			continue
		}
		ingestK8sObjects(ops, f, raw)
	}

	// Pass 3: backup pod logs → events
	for _, f := range files {
		if !detect.IsText(f.FileKind) {
			continue
		}
		content, ok := readText(d, f)
		if !ok {
			continue
		}
		ingestLogs(ops, f, content)
	}

	res := AnalysisResult{}
	for _, op := range ops {
		reconcile(op)
		res.Operations = append(res.Operations, *op)
	}
	// Deterministic order: dump → engine → namespace → name.
	sort.SliceStable(res.Operations, func(i, j int) bool {
		a, b := res.Operations[i], res.Operations[j]
		if a.DumpID != b.DumpID {
			return a.DumpID < b.DumpID
		}
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	res.Findings = deriveFindings(res.Operations)
	return res, nil
}

// --- pass 1: CRDs ---

func ingestCRDs(ops map[string]*Operation, f db.File, raw []byte) {
	for _, doc := range decodeAllDocs(raw) {
		for _, item := range flattenList(doc) {
			kind := strYAML(item, "kind")
			engine, ok := EngineFromKind(kind)
			if !ok {
				continue
			}
			name := strYAML(item, "metadata", "name")
			ns := strYAML(item, "metadata", "namespace")
			if name == "" {
				continue
			}
			key := opKey(f.DumpID, engine, ns, name)
			op := ops[key]
			if op == nil {
				op = &Operation{
					DumpID:      f.DumpID,
					Key:         key,
					Engine:      engine,
					Namespace:   ns,
					Name:        name,
					IsRestore:   IsRestoreKind(kind),
					SourceFiles: map[int64]bool{},
				}
				ops[key] = op
			}
			op.SourceFiles[f.ID] = true

			// Cluster name lives under different keys per engine.
			if cluster := firstNonEmpty(
				strYAML(item, "spec", "pxcCluster"),
				strYAML(item, "spec", "pgCluster"),
				strYAML(item, "spec", "clusterName"),
				strYAML(item, "spec", "dbClusterName"),
			); cluster != "" {
				op.Cluster = cluster
			}
			if t := strYAML(item, "spec", "type"); t != "" {
				op.Type = t
			}
			if t := strYAML(item, "status", "type"); t != "" && op.Type == "" {
				op.Type = t
			}
			if s := strYAML(item, "spec", "storageName"); s != "" {
				op.Storage = s
			}
			if s := strYAML(item, "status", "storageName"); s != "" && op.Storage == "" {
				op.Storage = s
			}
			if s := strYAML(item, "status", "repo", "name"); s != "" && op.Storage == "" {
				op.Storage = s
			}
			if dest := strYAML(item, "status", "destination"); dest != "" {
				op.Destination = dest
			}
			if owner := firstOwnerUID(item); owner != "" {
				op.OwnerUID = owner
			}
			if jn := strYAML(item, "status", "jobName"); jn != "" {
				op.JobName = jn
			}
			// Status mapping.
			raw := strYAML(item, "status", "state")
			if raw != "" {
				op.CRDStatus = NormalizeForEngine(engine, raw)
			}
			// Timestamps.
			if t, ok := ParseCRDTime(strYAML(item, "metadata", "creationTimestamp")); ok {
				if !op.HasStart || t.Before(op.Started) {
					op.Started = t
					op.HasStart = true
				}
				op.Events = append(op.Events, Event{
					DumpID: f.DumpID, FileID: f.ID, Timestamp: t, HasTime: true,
					Engine: engine, OpKey: key, Type: crEventType(op, "created"),
					Severity: SevInfo, Summary: kind + " created",
				})
			}
			for _, p := range []string{"completed", "completedAt", "finishTime", "finished", "lastTransition"} {
				if t, ok := ParseCRDTime(strYAML(item, "status", p)); ok {
					if !op.HasFinish || t.After(op.Completed) {
						op.Completed = t
						op.HasFinish = true
					}
					break
				}
			}
			if op.HasFinish {
				op.Events = append(op.Events, Event{
					DumpID: f.DumpID, FileID: f.ID, Timestamp: op.Completed, HasTime: true,
					Engine: engine, OpKey: key,
					Type:     crEventTypeFromStatus(op),
					Severity: severityForStatus(op.CRDStatus),
					Summary:  kind + " " + string(op.CRDStatus),
				})
			} else if op.CRDStatus == StatusRunning {
				op.Events = append(op.Events, Event{
					DumpID: f.DumpID, FileID: f.ID, Timestamp: op.Started, HasTime: op.HasStart,
					Engine: engine, OpKey: key, Type: crEventType(op, "running"),
					Severity: SevInfo, Summary: kind + " Running",
				})
			}
		}
	}
}

// --- pass 2: Jobs, Pods, Events ---

func ingestK8sObjects(ops map[string]*Operation, f db.File, raw []byte) {
	for _, doc := range decodeAllDocs(raw) {
		for _, item := range flattenList(doc) {
			kind := strYAML(item, "kind")
			switch kind {
			case "Job":
				attachJob(ops, f, item)
			case "Pod":
				attachPod(ops, f, item)
			case "Event":
				attachEvent(ops, f, item)
			}
		}
	}
}

func attachJob(ops map[string]*Operation, f db.File, item map[string]any) {
	jobName := strYAML(item, "metadata", "name")
	if jobName == "" {
		return
	}
	op := opFromJob(ops, f.DumpID, item)
	if op == nil {
		return
	}
	op.SourceFiles[f.ID] = true
	if op.JobName == "" {
		op.JobName = jobName
	}
	succeeded := numI64YAML(item, "status", "succeeded")
	failed := numI64YAML(item, "status", "failed")
	switch {
	case succeeded > 0:
		op.JobStatus = StatusSucceeded
		if t, ok := ParseCRDTime(strYAML(item, "status", "completionTime")); ok {
			op.Events = append(op.Events, Event{
				DumpID: f.DumpID, FileID: f.ID, Timestamp: t, HasTime: true,
				Engine: op.Engine, OpKey: op.Key, Type: EventBackupJobSucceed,
				Severity: SevInfo, Summary: "Job " + jobName + " succeeded",
			})
		}
	case failed > 0:
		// One or more failed Pod completions — count, but a single failed pod
		// alongside a succeeded one is not itself a hard failure of the Job.
		op.Warnings += int(failed)
		op.Events = append(op.Events, Event{
			DumpID: f.DumpID, FileID: f.ID, Engine: op.Engine, OpKey: op.Key,
			Type: EventBackupJobFailed, Severity: SevWarning,
			Summary: fmt.Sprintf("Job %s had %d failed pod completion(s)", jobName, failed),
		})
		if succeeded == 0 {
			op.JobStatus = StatusFailed
		}
	}
	if t, ok := ParseCRDTime(strYAML(item, "status", "startTime")); ok {
		op.Events = append(op.Events, Event{
			DumpID: f.DumpID, FileID: f.ID, Timestamp: t, HasTime: true,
			Engine: op.Engine, OpKey: op.Key, Type: EventBackupJobStarted,
			Severity: SevInfo, Summary: "Job " + jobName + " started",
		})
	}
}

func attachPod(ops map[string]*Operation, f db.File, item map[string]any) {
	podName := strYAML(item, "metadata", "name")
	if podName == "" {
		return
	}
	op := opFromPodName(ops, f.DumpID, podName, item)
	if op == nil {
		return
	}
	op.SourceFiles[f.ID] = true
	if op.PodName == "" {
		op.PodName = podName
	}
}

func attachEvent(ops map[string]*Operation, f db.File, item map[string]any) {
	involvedKind := strYAML(item, "involvedObject", "kind")
	involvedName := strYAML(item, "involvedObject", "name")
	if involvedName == "" {
		return
	}
	// Try to find an op whose Job or Pod name matches the involved object.
	op := findOpByJobOrPod(ops, f.DumpID, involvedName)
	if op == nil {
		return
	}
	op.SourceFiles[f.ID] = true
	msg := strYAML(item, "message")
	reason := strYAML(item, "reason")
	if reason == "" && msg == "" {
		return
	}
	evType := strYAML(item, "type")
	sev := SevInfo
	if evType == "Warning" {
		sev = SevWarning
		op.Warnings++
	}
	var ts time.Time
	hasTime := false
	for _, p := range []string{"eventTime", "lastTimestamp", "firstTimestamp"} {
		if t, ok := ParseCRDTime(strYAML(item, p)); ok {
			ts, hasTime = t, true
			break
		}
	}
	if !hasTime {
		if t, ok := ParseCRDTime(strYAML(item, "metadata", "creationTimestamp")); ok {
			ts, hasTime = t, true
		}
	}
	op.Events = append(op.Events, Event{
		DumpID: f.DumpID, FileID: f.ID, Timestamp: ts, HasTime: hasTime,
		Engine: op.Engine, OpKey: op.Key, Type: EventUnknown, Severity: sev,
		Summary: fmt.Sprintf("Event on %s/%s: %s — %s",
			involvedKind, involvedName, reason, truncate(msg, 160)),
	})
}

// --- pass 3: pod logs ---

func ingestLogs(ops map[string]*Operation, f db.File, content string) {
	op := opFromLogPath(ops, f.DumpID, f.RelativePath)
	if op == nil {
		return
	}
	op.SourceFiles[f.ID] = true
	lines := splitLines(content)
	var lastTime time.Time
	hasLast := false
	for i, line := range lines {
		ts, has := ParseTimestamp(line)
		if has {
			lastTime, hasLast = ts, true
		}
		v := ClassifyForEngine(op.Engine, line)
		if v.Type == "" {
			continue
		}
		ev := Event{
			DumpID: f.DumpID, FileID: f.ID, LineNumber: i + 1,
			Engine: op.Engine, OpKey: op.Key,
			Type: v.Type, Severity: v.Severity, Summary: v.Summary,
			Raw: truncate(line, 800),
		}
		if has {
			ev.Timestamp = ts
			ev.HasTime = true
		} else if hasLast {
			ev.Timestamp = lastTime
		}
		op.Events = append(op.Events, ev)

		if v.IsWarning {
			op.Warnings++
		}
		switch v.Outcome {
		case StatusSucceeded:
			if op.LogStatus != StatusFailed {
				op.LogStatus = StatusSucceeded
			}
		case StatusFailed:
			op.LogStatus = StatusFailed
			op.Errors++
		}
	}
}

// --- reconcile ---

func reconcile(op *Operation) {
	// Prefer CRD; otherwise Job; otherwise log evidence.
	switch {
	case op.CRDStatus != "" && op.CRDStatus != StatusUnknown:
		op.Status = op.CRDStatus
	case op.JobStatus != "":
		op.Status = op.JobStatus
	case op.LogStatus != "":
		op.Status = op.LogStatus
	default:
		op.Status = StatusUnknown
	}
	// Sort events for stable display.
	sort.SliceStable(op.Events, func(i, j int) bool {
		ei, ej := op.Events[i], op.Events[j]
		if ei.HasTime && !ej.HasTime {
			return true
		}
		if !ei.HasTime && ej.HasTime {
			return false
		}
		if ei.Timestamp.Equal(ej.Timestamp) {
			if ei.FileID != ej.FileID {
				return ei.FileID < ej.FileID
			}
			return ei.LineNumber < ej.LineNumber
		}
		return ei.Timestamp.Before(ej.Timestamp)
	})
}

// --- findings ---

func deriveFindings(ops []Operation) []LogFinding {
	var out []LogFinding
	for _, op := range ops {
		base := LogFinding{
			DumpID: op.DumpID, Engine: string(op.Engine),
			Namespace: op.Namespace, Cluster: op.Cluster, Name: op.Name,
			Status:  string(op.Status),
			Storage: op.Storage, Dest: truncate(op.Destination, 200),
			OpKey: op.Key,
		}
		if op.HasStart {
			base.Started = op.Started.UTC().Format(time.RFC3339)
		}
		if op.HasFinish {
			base.Completed = op.Completed.UTC().Format(time.RFC3339)
		}
		ruleBackup := "backup"
		if op.IsRestore {
			ruleBackup = "restore"
		}

		// Status-driven findings.
		switch op.Status {
		case StatusFailed:
			f := base
			f.Severity = SevCritical
			f.Rule = ruleBackup + ".failed"
			f.Title = fmt.Sprintf("%s/%s %s failed", op.Namespace, op.Name, op.Engine)
			f.Detail = "Status reported as Failed."
			out = append(out, f)
		case StatusRunning:
			f := base
			f.Severity = SevWarning
			f.Rule = ruleBackup + ".running"
			f.Title = fmt.Sprintf("%s/%s %s still Running at dump time", op.Namespace, op.Name, op.Engine)
			f.Detail = "Backup did not reach a terminal status in the captured dump."
			out = append(out, f)
		case StatusUnknown:
			if len(op.Events) > 0 {
				f := base
				f.Severity = SevWarning
				f.Rule = ruleBackup + ".unknown_status"
				f.Title = fmt.Sprintf("%s/%s %s has unknown status", op.Namespace, op.Name, op.Engine)
				f.Detail = "Backup has log/event evidence but no resolved status."
				out = append(out, f)
			}
		}

		// Log evidence findings (cap at one error / one warning per op).
		var sawErr, sawWarn bool
		for _, ev := range op.Events {
			switch ev.Type {
			case EventBackupFailed:
				if sawErr {
					continue
				}
				sawErr = true
				f := base
				f.Severity = SevCritical
				f.Rule = "backup.log_error"
				f.Title = fmt.Sprintf("Backup %s/%s logs report failure", op.Namespace, op.Name)
				f.Detail = ev.Summary
				f.FileID = ev.FileID
				f.LineNumber = ev.LineNumber
				out = append(out, f)
			case EventBackupWarning:
				if sawWarn {
					continue
				}
				sawWarn = true
				rule := "backup.log_warning"
				switch op.Engine {
				case EnginePXC:
					rule = "backup.xtrabackup_warning"
				case EnginePostgres:
					rule = "backup.pgbackrest_warning"
				case EngineMongoDB:
					rule = "backup.pbm_warning"
				}
				f := base
				f.Severity = SevWarning
				f.Rule = rule
				f.Title = fmt.Sprintf("Warning in %s/%s backup logs", op.Namespace, op.Name)
				f.Detail = ev.Summary
				f.FileID = ev.FileID
				f.LineNumber = ev.LineNumber
				out = append(out, f)
			}
		}

		// Missing storage / destination on a non-failed op.
		if op.Status != StatusFailed {
			if op.Storage == "" {
				f := base
				f.Severity = SevWarning
				f.Rule = "backup.storage_missing"
				f.Title = fmt.Sprintf("%s/%s %s has no storage name recorded", op.Namespace, op.Name, op.Engine)
				out = append(out, f)
			}
			if op.Destination == "" && op.CRDStatus == StatusSucceeded {
				f := base
				f.Severity = SevWarning
				f.Rule = "backup.destination_missing"
				f.Title = fmt.Sprintf("%s/%s %s succeeded but reports no destination", op.Namespace, op.Name, op.Engine)
				out = append(out, f)
			}
		}

		// CRD/log mismatch: CRD says X, log evidence says Y.
		if op.CRDStatus != "" && op.LogStatus != "" && op.CRDStatus != op.LogStatus &&
			op.CRDStatus != StatusUnknown && op.LogStatus != StatusUnknown {
			f := base
			f.Severity = SevWarning
			f.Rule = "backup.cr_log_mismatch"
			f.Title = fmt.Sprintf("%s/%s %s status disagrees: CRD=%s, log=%s",
				op.Namespace, op.Name, op.Engine, op.CRDStatus, op.LogStatus)
			f.Detail = "Backup CRD-reported status does not match evidence from backup pod logs."
			out = append(out, f)
		}
	}
	return out
}

// --- YAML helpers (kept local to avoid lifting analyze's privates) ---

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
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func flattenList(doc map[string]any) []map[string]any {
	if strYAML(doc, "kind") != "List" {
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

func strYAML(m map[string]any, keys ...string) string {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	switch v := cur.(type) {
	case string:
		return v
	case int:
		return fmt.Sprint(v)
	case int64:
		return fmt.Sprint(v)
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

func numI64YAML(m map[string]any, keys ...string) int64 {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = obj[k]
	}
	switch v := cur.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

func firstOwnerUID(item map[string]any) string {
	refs, _ := item["metadata"].(map[string]any)
	if refs == nil {
		return ""
	}
	arr, _ := refs["ownerReferences"].([]any)
	for _, r := range arr {
		if m, ok := r.(map[string]any); ok {
			if u, ok := m["uid"].(string); ok && u != "" {
				return u
			}
		}
	}
	return ""
}

// opKey returns the canonical map key for an Operation.
func opKey(dumpID int64, engine Engine, namespace, name string) string {
	return fmt.Sprintf("%d|%s|%s|%s", dumpID, engine, namespace, name)
}

// opFromJob picks the Operation a Job belongs to via ownerReferences first,
// then via name matching.
func opFromJob(ops map[string]*Operation, dumpID int64, item map[string]any) *Operation {
	jobNS := strYAML(item, "metadata", "namespace")
	jobName := strYAML(item, "metadata", "name")
	if owner := firstOwnerUID(item); owner != "" {
		for _, op := range ops {
			if op.DumpID == dumpID && op.OwnerUID == owner {
				return op
			}
		}
		// Match by owner kind+name (matches CRDs without owner UID propagation).
		refs, _ := item["metadata"].(map[string]any)
		if refs != nil {
			if arr, ok := refs["ownerReferences"].([]any); ok {
				for _, r := range arr {
					if m, ok := r.(map[string]any); ok {
						kind := strYAML(m, "kind")
						name := strYAML(m, "name")
						if engine, ok := EngineFromKind(kind); ok {
							key := opKey(dumpID, engine, jobNS, name)
							if op := ops[key]; op != nil {
								return op
							}
						}
					}
				}
			}
		}
	}
	// Fall back to a name prefix match on either engine.
	if op := findOpByJobOrPod(ops, dumpID, jobName); op != nil {
		return op
	}
	return nil
}

// opFromPodName finds the Operation a backup pod logs into.
func opFromPodName(ops map[string]*Operation, dumpID int64, podName string, item map[string]any) *Operation {
	// Owner reference (Job) → Job's owner CRD.
	refs, _ := item["metadata"].(map[string]any)
	if refs != nil {
		if arr, ok := refs["ownerReferences"].([]any); ok {
			for _, r := range arr {
				if m, ok := r.(map[string]any); ok {
					kind := strYAML(m, "kind")
					name := strYAML(m, "name")
					if engine, ok := EngineFromKind(kind); ok {
						key := opKey(dumpID, engine, strYAML(item, "metadata", "namespace"), name)
						if op := ops[key]; op != nil {
							return op
						}
					}
					if kind == "Job" {
						// We don't have the Job here; do a name-prefix lookup.
						if op := findOpByJobOrPod(ops, dumpID, name); op != nil {
							return op
						}
					}
				}
			}
		}
	}
	return findOpByJobOrPod(ops, dumpID, podName)
}

// findOpByJobOrPod walks ops looking for a match against an emitted name.
// Used by Pod/Event attachment when ownerReferences are absent or ambiguous.
func findOpByJobOrPod(ops map[string]*Operation, dumpID int64, name string) *Operation {
	if name == "" {
		return nil
	}
	if key, ok := PXCPodKey(name); ok {
		for _, op := range ops {
			if op.DumpID == dumpID && op.Engine == EnginePXC && op.Name == key {
				return op
			}
		}
	}
	if key, ok := PGPodKey(name); ok {
		for _, op := range ops {
			if op.DumpID == dumpID && op.Engine == EnginePostgres && strings.HasPrefix(op.Name, key) {
				return op
			}
		}
	}
	// Direct name == op.JobName / op.Name match.
	for _, op := range ops {
		if op.DumpID != dumpID {
			continue
		}
		if op.JobName != "" && op.JobName == name {
			return op
		}
		if op.Name == name {
			return op
		}
	}
	return nil
}

// opFromLogPath picks the Operation a "<...>/<pod-name>/logs.txt" file logs.
// Returns nil for paths that don't look like a backup pod log.
func opFromLogPath(ops map[string]*Operation, dumpID int64, relPath string) *Operation {
	parts := strings.Split(relPath, "/")
	if len(parts) < 2 {
		return nil
	}
	podName := parts[len(parts)-2]
	base := path.Base(relPath)
	if base != "logs.txt" && !strings.HasSuffix(base, ".log") {
		return nil
	}
	return findOpByJobOrPod(ops, dumpID, podName)
}

// --- misc helpers ---

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n")
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func crEventType(op *Operation, suffix string) EventType {
	switch {
	case op.IsRestore && suffix == "created":
		return EventRestoreCRCreated
	case op.IsRestore && suffix == "running":
		return EventRestoreCRRunning
	case op.IsRestore && suffix == "succeeded":
		return EventRestoreCRSucceed
	case op.IsRestore && suffix == "failed":
		return EventRestoreCRFailed
	case suffix == "created":
		return EventBackupCRCreated
	case suffix == "running":
		return EventBackupCRRunning
	case suffix == "succeeded":
		return EventBackupCRSucceeded
	case suffix == "failed":
		return EventBackupCRFailed
	}
	return EventUnknown
}

func crEventTypeFromStatus(op *Operation) EventType {
	switch op.CRDStatus {
	case StatusSucceeded:
		return crEventType(op, "succeeded")
	case StatusFailed:
		return crEventType(op, "failed")
	case StatusRunning:
		return crEventType(op, "running")
	}
	return EventUnknown
}

func severityForStatus(s Status) string {
	switch s {
	case StatusFailed:
		return SevError
	case StatusRunning, StatusPending:
		return SevInfo
	}
	return SevInfo
}

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
