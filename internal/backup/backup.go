// Package backup parses Percona backup/restore CRDs, Jobs, Events, and backup
// pod logs from imported files, correlates them into per-backup Operations,
// and emits a Backup Timeline view + concerns findings.
//
// Everything here is derived: the raw BLOB in SQLite is never mutated.
package backup

import (
	"regexp"
	"strings"
	"time"
)

// Engine names the backup engine family for an Operation. The "unknown" engine
// is used when we have backup pod log evidence but no matching CRD/Job — the
// timeline still shows it; concerns can flag it as backup.unknown_status.
type Engine string

const (
	EnginePXC      Engine = "pxc"
	EnginePostgres Engine = "postgres"
	EngineMongoDB  Engine = "mongodb"
	EngineEverest  Engine = "everest"
	EngineUnknown  Engine = "unknown"
)

// Status is the normalized lifecycle phase for an Operation. Engine-specific
// raw status strings are mapped into this enum by Normalize*Status.
type Status string

const (
	StatusSucceeded Status = "Succeeded"
	StatusFailed    Status = "Failed"
	StatusRunning   Status = "Running"
	StatusPending   Status = "Pending"
	StatusUnknown   Status = "Unknown"
)

// EventType classifies a single timeline event. See the spec for the full
// vocabulary — the constants here match the public list.
type EventType string

const (
	EventBackupCRCreated   EventType = "backup_cr_created"
	EventBackupCRRunning   EventType = "backup_cr_running"
	EventBackupCRSucceeded EventType = "backup_cr_succeeded"
	EventBackupCRFailed    EventType = "backup_cr_failed"
	EventBackupJobCreated  EventType = "backup_job_created"
	EventBackupJobStarted  EventType = "backup_job_started"
	EventBackupJobSucceed  EventType = "backup_job_succeeded"
	EventBackupJobFailed   EventType = "backup_job_failed"
	EventBackupPodStarted  EventType = "backup_pod_started"
	EventBackupCmdRequest  EventType = "backup_command_requested"
	EventBackupUploadStart EventType = "backup_upload_started"
	EventBackupUploadDone  EventType = "backup_upload_completed"
	EventBackupCompleted   EventType = "backup_completed"
	EventBackupFailed      EventType = "backup_failed"
	EventBackupWarning     EventType = "backup_warning"
	EventRestoreCRCreated  EventType = "restore_cr_created"
	EventRestoreCRRunning  EventType = "restore_cr_running"
	EventRestoreCRSucceed  EventType = "restore_cr_succeeded"
	EventRestoreCRFailed   EventType = "restore_cr_failed"
	EventUnknown           EventType = "unknown"
)

// Severity strings line up with analyze.Severity so analyze.fromBackupFinding
// can fold them straight into the concerns pipeline.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevError    = "error"
	SevCritical = "critical"
)

// Event is one structured timeline entry. Events without a parseable timestamp
// have HasTime=false; aggregation places them after timestamped events from
// the same source file.
type Event struct {
	DumpID     int64
	FileID     int64
	LineNumber int
	Timestamp  time.Time
	HasTime    bool
	Engine     Engine
	OpKey      string // canonical key matching the owning Operation
	Type       EventType
	Severity   string
	Summary    string
	Raw        string
}

// Operation is one logical backup or restore aggregated across CRD + Job +
// Pod + log sources. Fields preserve provenance: SourceFiles lists every
// file that contributed at least one event so the file detail page can show
// reverse links.
type Operation struct {
	DumpID      int64
	Key         string // canonical (dumpID|engine|namespace|name)
	Engine      Engine
	Namespace   string
	Cluster     string
	Name        string
	IsRestore   bool
	Type        string
	Storage     string
	Destination string

	CRDStatus Status // raw status from the CRD, normalized
	JobStatus Status // derived from Job.status.succeeded/failed
	LogStatus Status // derived from log evidence
	Status    Status // final reconciled status

	Started   time.Time
	Completed time.Time
	HasStart  bool
	HasFinish bool

	Warnings int
	Errors   int

	JobName  string
	PodName  string
	OwnerUID string

	Events      []Event
	SourceFiles map[int64]bool
}

// Duration returns Completed - Started when both timestamps are known,
// otherwise "".
func (o Operation) Duration() string {
	if !o.HasStart || !o.HasFinish {
		return ""
	}
	d := o.Completed.Sub(o.Started)
	if d < 0 {
		return ""
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Second).String()
}

// EngineFromKind returns the engine bucket for a backup/restore CRD kind.
func EngineFromKind(kind string) (Engine, bool) {
	switch kind {
	case "PerconaXtraDBClusterBackup", "PerconaXtraDBClusterRestore":
		return EnginePXC, true
	case "PerconaPGBackup", "PerconaPGRestore":
		return EnginePostgres, true
	case "PerconaServerMongoDBBackup", "PerconaServerMongoDBRestore":
		return EngineMongoDB, true
	case "DatabaseClusterBackup", "DatabaseClusterRestore":
		return EngineEverest, true
	}
	return "", false
}

// IsRestoreKind reports whether the given CRD kind represents a restore.
func IsRestoreKind(kind string) bool {
	return strings.Contains(kind, "Restore")
}

// --- status normalization ---

// NormalizePXCStatus maps PXC CR status strings to the canonical enum.
func NormalizePXCStatus(s string) Status {
	switch s {
	case "Succeeded":
		return StatusSucceeded
	case "Running", "Starting":
		return StatusRunning
	case "Failed", "Error":
		return StatusFailed
	case "":
		return ""
	}
	return StatusUnknown
}

// NormalizePGStatus maps Postgres CR status strings.
func NormalizePGStatus(s string) Status {
	switch s {
	case "Succeeded":
		return StatusSucceeded
	case "Running":
		return StatusRunning
	case "Failed":
		return StatusFailed
	case "":
		return ""
	}
	return StatusUnknown
}

// NormalizeMongoStatus maps PSMDB CR status strings.
func NormalizeMongoStatus(s string) Status {
	switch strings.ToLower(s) {
	case "ready", "succeeded":
		return StatusSucceeded
	case "running":
		return StatusRunning
	case "error", "failed":
		return StatusFailed
	case "requested", "new", "waiting":
		return StatusPending
	case "":
		return ""
	}
	return StatusUnknown
}

// NormalizeEverestStatus maps DatabaseClusterBackup status strings.
func NormalizeEverestStatus(s string) Status {
	switch s {
	case "Succeeded":
		return StatusSucceeded
	case "Running", "Starting", "InProgress":
		return StatusRunning
	case "Failed", "Error":
		return StatusFailed
	case "":
		return ""
	}
	return StatusUnknown
}

// NormalizeForEngine routes to the engine-specific normalizer.
func NormalizeForEngine(engine Engine, raw string) Status {
	switch engine {
	case EnginePXC:
		return NormalizePXCStatus(raw)
	case EnginePostgres:
		return NormalizePGStatus(raw)
	case EngineMongoDB:
		return NormalizeMongoStatus(raw)
	case EngineEverest:
		return NormalizeEverestStatus(raw)
	}
	return StatusUnknown
}

// --- timestamp parsing ---

var (
	// time="2026-05-28T10:59:49Z" — logfmt header used by pgBackRest helper.
	logfmtTimeRe = regexp.MustCompile(`time="([^"]+)"`)
	// 2026-05-28T11:08:15Z and 2026-05-28T12:53:25.743853Z — MySQL/CR style.
	isoTopRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
	// 2026-05-28 12:56:18.206  INFO: / 2026-05-28 12:56:18 [INFO]
	xbScriptRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)`)
	// MongoDB JSON log: {"t":{"$date":"2026-05-28T11:14:29.730+00:00"},...}
	mongoJSONRe = regexp.MustCompile(`"t":\s*\{\s*"\$date"\s*:\s*"([^"]+)"`)
)

// ParseTimestamp returns the best-effort timestamp for one log line. ok=false
// when no parseable timestamp is present; callers may then inherit the
// previous line's timestamp.
func ParseTimestamp(line string) (time.Time, bool) {
	if m := logfmtTimeRe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
			return t, true
		}
	}
	if m := mongoJSONRe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
			return t, true
		}
	}
	if m := isoTopRe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
			return t, true
		}
	}
	if m := xbScriptRe.FindStringSubmatch(line); m != nil {
		s := strings.Replace(m[1], " ", "T", 1) + "Z"
		if t, ok := tryParseTime(s); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

func tryParseTime(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999-07:00",
		"2006-01-02T15:04:05-07:00",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ParseCRDTime parses a CR-level timestamp field (creationTimestamp,
// status.completed, status.startTime, etc.). Returns ok=false on failure.
func ParseCRDTime(s string) (time.Time, bool) { return tryParseTime(s) }

// --- log classification ---

// LogVerdict is the per-line classification produced by a log classifier.
type LogVerdict struct {
	Type     EventType
	Severity string
	Summary  string
	// Outcome reports whether the line is evidence of success / failure /
	// warning at the operation level. It feeds Operation.LogStatus aggregation.
	Outcome Status
	// IsWarning marks lines that should increment Operation.Warnings without
	// flipping LogStatus to Failed. Used for pgBackRest WARN: lines.
	IsWarning bool
}

// ClassifyXtrabackupLine reads one xtrabackup / SST-script log line and
// returns a verdict. Returns Type="" when the line is uninteresting noise.
func ClassifyXtrabackupLine(line string) LogVerdict {
	l := strings.TrimRight(line, "\r\n")
	switch {
	case strings.Contains(l, "Backup was finished successfully"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: "Backup was finished successfully", Outcome: StatusSucceeded}
	case strings.Contains(l, "Backup is uploaded to s3 successfully"):
		return LogVerdict{Type: EventBackupUploadDone, Severity: SevInfo,
			Summary: "Backup uploaded to S3", Outcome: StatusSucceeded}
	case strings.Contains(l, "SST script ended gracefully"),
		strings.Contains(l, "sst-script finished with code (wait): 0"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: "SST script ended gracefully", Outcome: StatusSucceeded}
	case strings.Contains(l, "Backup finished"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: "Backup finished", Outcome: StatusSucceeded}
	case strings.Contains(l, "Garbd returns 0"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: "Garbd returns 0"}

	case strings.Contains(l, "SST_FAILED"),
		strings.Contains(l, "xbcloud: error"),
		strings.Contains(l, "xtrabackup: error"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevCritical,
			Summary: shortify(l), Outcome: StatusFailed}
	case strings.Contains(l, "Backup failed"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevCritical,
			Summary: "Backup failed", Outcome: StatusFailed}

	case strings.Contains(l, "level=error"), strings.Contains(l, "[ERROR]"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevError,
			Summary: shortify(l), Outcome: StatusFailed}
	case strings.Contains(l, "level=warning"), strings.Contains(l, "[Warning]"), strings.Contains(l, "WARN:"):
		return LogVerdict{Type: EventBackupWarning, Severity: SevWarning,
			Summary: shortify(l), IsWarning: true}
	}
	return LogVerdict{}
}

// ClassifyPgBackRestLine classifies pgBackRest / crunchy-pgbackrest log lines.
// WARN lines and stderr hash-mismatch warnings are marked IsWarning so they
// attach to the operation's warning count without flipping CRD success.
func ClassifyPgBackRestLine(line string) LogVerdict {
	l := strings.TrimRight(line, "\r\n")
	switch {
	case strings.Contains(l, "crunchy-pgbackrest starts"):
		return LogVerdict{Type: EventBackupPodStarted, Severity: SevInfo,
			Summary: "crunchy-pgbackrest starts"}
	case strings.Contains(l, "backrest backup command requested"):
		return LogVerdict{Type: EventBackupCmdRequest, Severity: SevInfo,
			Summary: "backrest backup command requested"}
	case strings.Contains(l, "crunchy-pgbackrest ends"),
		strings.Contains(l, "command terminated with exit code 0"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: "pgbackrest completed", Outcome: StatusSucceeded}

	case strings.Contains(l, "level=fatal"),
		strings.Contains(l, "command terminated with exit code 1"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevCritical,
			Summary: shortify(l), Outcome: StatusFailed}
	case strings.Contains(l, "[pgbackrest:stderr]"):
		// stderr lines without an explicit fatal are warnings (hash mismatch,
		// repository may run out of space). Do not flip success → failed.
		return LogVerdict{Type: EventBackupWarning, Severity: SevWarning,
			Summary: shortify(l), IsWarning: true}
	case strings.Contains(l, "WARN:"),
		strings.Contains(l, "repository may run out of space"),
		strings.Contains(l, "does not match local hash"):
		return LogVerdict{Type: EventBackupWarning, Severity: SevWarning,
			Summary: shortify(l), IsWarning: true}
	case strings.Contains(l, "ERROR:"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevError,
			Summary: shortify(l), Outcome: StatusFailed}
	}
	return LogVerdict{}
}

// ClassifyPBMLine classifies MongoDB PBM / backup-agent log lines. JSON log
// format is supported by inspecting the unparsed line for marker substrings;
// the JSON timestamp is extracted by ParseTimestamp upstream.
func ClassifyPBMLine(line string) LogVerdict {
	l := strings.TrimRight(line, "\r\n")
	switch {
	case strings.Contains(l, "operator-pbm-ctl"), strings.Contains(l, "backup-agent"):
		// Authentication / liveness lines from the operator side — pod started.
		if strings.Contains(l, "Successfully authenticated") {
			return LogVerdict{Type: EventBackupPodStarted, Severity: SevInfo,
				Summary: "PBM agent authenticated"}
		}
	}
	switch {
	case strings.Contains(l, "snapshot upload"), strings.Contains(l, "pbm upload"):
		return LogVerdict{Type: EventBackupUploadStart, Severity: SevInfo,
			Summary: shortify(l)}
	case strings.Contains(l, "pbm complete"), strings.Contains(l, "snapshot finished"),
		strings.Contains(l, "backup done"):
		return LogVerdict{Type: EventBackupCompleted, Severity: SevInfo,
			Summary: shortify(l), Outcome: StatusSucceeded}
	case strings.Contains(l, "pbm error"), strings.Contains(l, "backup failed"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevCritical,
			Summary: shortify(l), Outcome: StatusFailed}
	case strings.Contains(l, "level=error"):
		return LogVerdict{Type: EventBackupFailed, Severity: SevError,
			Summary: shortify(l), Outcome: StatusFailed}
	case strings.Contains(l, "level=warning"):
		return LogVerdict{Type: EventBackupWarning, Severity: SevWarning,
			Summary: shortify(l), IsWarning: true}
	}
	return LogVerdict{}
}

// ClassifyForEngine routes to the right classifier.
func ClassifyForEngine(engine Engine, line string) LogVerdict {
	switch engine {
	case EnginePXC:
		return ClassifyXtrabackupLine(line)
	case EnginePostgres:
		return ClassifyPgBackRestLine(line)
	case EngineMongoDB:
		return ClassifyPBMLine(line)
	}
	return LogVerdict{}
}

// --- pod name <-> backup CRD correlation ---

var (
	// xb-backup-<short>-<podSuffix>  pod name → matches CRD "backup-<short>".
	pxcPodRe = regexp.MustCompile(`^xb-backup-([a-z0-9]+)-[a-z0-9]+$`)
	// postgresql-<cluster>-backup-<short>-<podSuffix> → matches CRD with name
	// containing "<cluster>-backup-<short>".
	pgPodRe = regexp.MustCompile(`^([a-z0-9-]+)-backup-([a-z0-9]+)-[a-z0-9]+$`)
)

// PXCPodKey returns the short CRD name component matching a backup pod.
// Example: "xb-backup-ehs-dsblr" → "backup-ehs".
func PXCPodKey(pod string) (string, bool) {
	if m := pxcPodRe.FindStringSubmatch(pod); m != nil {
		return "backup-" + m[1], true
	}
	return "", false
}

// PGPodKey returns the prefix that should match a PerconaPGBackup CRD name.
// Example: "postgresql-awn-backup-k5pr-875zc" → "postgresql-awn-backup-k5pr".
// Callers should look up the CRD by name prefix match — the CRD's full name
// often has another random suffix.
func PGPodKey(pod string) (string, bool) {
	if m := pgPodRe.FindStringSubmatch(pod); m != nil {
		return m[1] + "-backup-" + m[2], true
	}
	return "", false
}

// --- helpers ---

func shortify(s string) string {
	s = strings.TrimSpace(s)
	// Drop everything past the first " | " or " --" for readability.
	if i := strings.Index(s, "msg=\""); i >= 0 {
		rest := s[i+len(`msg="`):]
		if j := strings.Index(rest, "\""); j > 0 {
			return truncate(rest[:j], 220)
		}
	}
	return truncate(s, 220)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
