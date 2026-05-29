// Package pxc parses Percona XtraDB Cluster / Galera / MySQL / PMM log lines
// from imported text files and derives a side-by-side multi-node timeline.
//
// All parsing is read-only — the raw BLOB stored in SQLite is the canonical
// source of truth. This package never mutates it.
package pxc

import (
	"regexp"
	"strings"
	"time"
)

// EventType is the canonical classification for a single timeline event.
type EventType string

const (
	PMMSetupStarted     EventType = "pmm_setup_started"
	PMMRegistered       EventType = "pmm_registered"
	PMMConnected        EventType = "pmm_connected"
	PMMServiceAdded     EventType = "pmm_service_added"
	ExporterStarted     EventType = "exporter_started"
	MySQLStart          EventType = "mysql_start"
	MySQLReady          EventType = "mysql_ready"
	AdminReady          EventType = "admin_ready"
	InnoDBInitialized   EventType = "innodb_initialized"
	PXCUpgradeCompleted EventType = "pxc_upgrade_completed"
	ClusterBootstrap    EventType = "cluster_bootstrap"
	ClusterJoin         EventType = "cluster_join"
	ViewChange          EventType = "view_change"
	MemberJoined        EventType = "member_joined"
	MemberSynced        EventType = "member_synced"
	StateTransferReq    EventType = "state_transfer_requested"
	StateTransferDone   EventType = "state_transfer_completed"
	SSTStarted          EventType = "sst_started"
	SSTProgress         EventType = "sst_progress"
	SSTCompleted        EventType = "sst_completed"
	SSTSent             EventType = "sst_sent"
	ISTRequested        EventType = "ist_requested"
	ISTStarted          EventType = "ist_started"
	ISTCompleted        EventType = "ist_completed"
	DonorSelected       EventType = "donor_selected"
	DonorDesynced       EventType = "donor_desynced"
	DonorJoined         EventType = "donor_joined"
	ServerStatusChange  EventType = "server_status_change"
	WSREPReady          EventType = "wsrep_ready"
	Warning             EventType = "warning"
	Error               EventType = "error"
	Crash               EventType = "crash"
	Restart             EventType = "restart"
	Unknown             EventType = "unknown"
)

// Severity strings line up with analyze.Severity for downstream integration.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevError    = "error"
	SevCritical = "critical"
)

// Event is one classified line. Timestamps that could not be parsed inherit
// the previous line's timestamp from the same file; HasTime tracks whether the
// timestamp came from the line itself.
type Event struct {
	DumpID     int64
	FileID     int64
	LineNumber int
	Node       string
	Timestamp  time.Time
	HasTime    bool
	Type       EventType
	Severity   string
	Component  string
	Summary    string
	Raw        string
	OldState   string
	NewState   string
}

// ParseFile classifies every interesting line in content and returns events
// in file order. Timestamps without a date inherit the previous timestamp.
//
// pathNode is the canonical node identity (typically the parent directory
// name of the file's relative path). When pathNode is non-empty, every event
// is attributed to pathNode — explicit "Node name:" lines and pod-name tokens
// in the body are not allowed to rewrite it, so the same physical node
// always shows up under exactly one column in the side-by-side timeline.
// When pathNode is empty, identity falls back to explicit log signals, then
// to in-line pod-name tokens, then to "unknown".
func ParseFile(dumpID, fileID int64, pathNode, content string) []Event {
	if content == "" {
		return nil
	}
	lines := splitLines(content)
	var events []Event
	var lastTime time.Time
	hasLastTime := false
	lastNode := pathNode

	for i, line := range lines {
		ts, hasTime := parseTimestamp(line)
		if hasTime {
			lastTime = ts
			hasLastTime = true
		}
		// Update node identity from explicit lines only when we don't already
		// have a canonical pathNode for this file.
		if pathNode == "" {
			if n := nodeFromExplicit(line); n != "" {
				lastNode = normalizeNode(n)
			}
		}

		etype, sev, comp, summary, oldState, newState := classify(line)
		if etype == "" {
			continue
		}

		node := lastNode
		if pathNode == "" {
			if c := nodeFromContent(line); c != "" {
				node = c
			}
		}
		if node == "" {
			node = "unknown"
		}

		ev := Event{
			DumpID:     dumpID,
			FileID:     fileID,
			LineNumber: i + 1,
			Node:       node,
			Timestamp:  ts,
			HasTime:    hasTime,
			Type:       etype,
			Severity:   sev,
			Component:  comp,
			Summary:    summary,
			Raw:        truncate(line, 800),
			OldState:   oldState,
			NewState:   newState,
		}
		if !hasTime && hasLastTime {
			ev.Timestamp = lastTime
		}
		events = append(events, ev)
	}
	return events
}

// ContainsPXCMarkers returns true if content looks like a PXC/Galera/MySQL/PMM
// candidate log. Callers can use this to skip clearly-irrelevant text files.
func ContainsPXCMarkers(content string) bool {
	if content == "" {
		return false
	}
	for _, m := range markerTerms {
		if strings.Contains(content, m) {
			return true
		}
	}
	return false
}

var markerTerms = []string{
	"PXC", "Percona XtraDB Cluster", "mysqld", "Galera", "WSREP",
	"WSREP-SST", "wsrep_", "gcomm", "pmm-agent", "pmm-admin",
	"mysqld_exporter", "node_exporter",
	"ready for connections", "Synchronized with group",
}

// PXCNodeFromPath returns the parent-directory node name when the relative
// path looks like a PXC pod log path: ".../<...pxc-N>/<file>". ok=false when
// the path does not match.
func PXCNodeFromPath(relPath string) (string, bool) {
	if m := pxcPodPathRe.FindStringSubmatch(relPath); m != nil {
		return m[1], true
	}
	return "", false
}

var pxcPodPathRe = regexp.MustCompile(`(?:^|/)([A-Za-z0-9-]*pxc-\d+)(?:/[^/]+)+$`)

// ParentDirNode returns the last directory segment in relPath ("" if none).
// Useful for callers that want a fallback identity when the path does not
// match the PXC pod pattern.
func ParentDirNode(relPath string) string {
	parts := strings.Split(relPath, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// --- timestamp parsing ---

var (
	// time="2026-05-28T12:51:45.934+00:00"
	logfmtTimeRe = regexp.MustCompile(`time="([^"]+)"`)
	// 2026-05-28T12:53:25.743853Z at the start of the line
	mysqlISORe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)`)
	// 2026/05/28 12:51:46  (peer-list / shell timestamps)
	slashedTimeRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
	// Plain ISO without trailing Z anywhere — last resort.
	looseISORe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
)

func parseTimestamp(line string) (time.Time, bool) {
	if m := logfmtTimeRe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
			return t, true
		}
	}
	if m := mysqlISORe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
			return t, true
		}
	}
	if m := slashedTimeRe.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse("2006/01/02 15:04:05", m[1]); err == nil {
			return t.UTC(), true
		}
	}
	if m := looseISORe.FindStringSubmatch(line); m != nil {
		if t, ok := tryParseTime(m[1]); ok {
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

// --- node identity ---

var (
	explicitNodeRe = regexp.MustCompile(`(?:Node name|Service name)\s*:\s*(\S+)`)
	contentNodeRe  = regexp.MustCompile(`([A-Za-z0-9-]+-pxc-\d+)`)
)

func nodeFromExplicit(line string) string {
	if m := explicitNodeRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

func nodeFromContent(line string) string {
	// Try short pod name first.
	if m := contentNodeRe.FindStringSubmatch(line); m != nil {
		return normalizeNode(m[1])
	}
	return ""
}

// normalizeNode strips trailing FQDN segments. It does NOT strip a leading
// namespace prefix (we can't reliably know it from one line) — the timeline
// renderer relies on the file-path-derived node for canonical naming.
func normalizeNode(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// --- classification ---

func classify(raw string) (etype EventType, sev, component, summary, oldState, newState string) {
	line := strings.TrimRight(raw, "\r\n ")
	if line == "" {
		return "", "", "", "", "", ""
	}
	sev = classifySeverity(line)
	component = detectComponent(line)

	switch {
	// Order matters: more specific patterns first.
	case strings.Contains(line, "Synchronized with group"):
		return WSREPReady, SevInfo, "wsrep", "Synchronized with group, ready for connections", "", ""

	case strings.Contains(line, "Admin interface ready for connections"):
		return AdminReady, SevInfo, "mysqld", "Admin interface ready for connections", "", ""

	case strings.Contains(line, "X Plugin ready for connections"):
		return MySQLReady, SevInfo, "mysqld", "X Plugin ready for connections", "", ""

	case strings.Contains(line, "ready for connections"):
		return MySQLReady, SevInfo, "mysqld", "mysqld ready for connections", "", ""

	case strings.Contains(line, "Server status change"):
		o, n := parseStateChange(line)
		return ServerStatusChange, SevInfo, "wsrep", "Server status change " + o + " → " + n, o, n

	case strings.Contains(line, "SST completed"):
		return SSTCompleted, SevInfo, "wsrep", "SST completed", "", ""

	case strings.Contains(line, "SST sent"):
		return SSTSent, SevInfo, "galera", "SST sent", "", ""

	case strings.Contains(line, "Shifting SYNCED -> DONOR/DESYNCED"):
		return DonorDesynced, SevInfo, "galera", "Shifting SYNCED → DONOR/DESYNCED", "SYNCED", "DONOR/DESYNCED"

	case strings.Contains(line, "Shifting DONOR/DESYNCED -> JOINED"):
		return DonorJoined, SevInfo, "galera", "Shifting DONOR/DESYNCED → JOINED", "DONOR/DESYNCED", "JOINED"

	case strings.Contains(line, "requested state transfer"):
		if strings.Contains(line, "Selected") {
			return DonorSelected, SevInfo, "galera", shortify(line, "requested state transfer"), "", ""
		}
		return StateTransferReq, SevInfo, "galera", shortify(line, "requested state transfer"), "", ""

	case strings.Contains(line, "Requesting state transfer: success"):
		return StateTransferReq, SevInfo, "galera", "Requesting state transfer", "", ""

	case strings.Contains(line, "State transfer required"):
		return StateTransferReq, SevInfo, "galera", "State transfer required", "", ""

	case strings.Contains(line, "State transfer to") && strings.Contains(line, "complete"):
		return StateTransferDone, SevInfo, "galera", shortify(line, "complete"), "", ""

	case strings.Contains(line, "State transfer from") && strings.Contains(line, "complete"):
		return StateTransferDone, SevInfo, "galera", shortify(line, "complete"), "", ""

	case strings.Contains(line, "Initiating SST/IST transfer on DONOR side"):
		return SSTStarted, SevInfo, "wsrep", "Initiating SST/IST transfer (DONOR)", "", ""

	case strings.Contains(line, "Receiving IST"):
		return ISTStarted, SevInfo, "galera", "Receiving IST", "", ""

	case strings.Contains(line, "IST received"):
		return ISTCompleted, SevInfo, "galera", "IST received", "", ""

	case strings.Contains(line, "InnoDB initialization has ended"):
		return InnoDBInitialized, SevInfo, "innodb", "InnoDB initialization complete", "", ""

	case strings.Contains(line, "Percona XtraDB Cluster: Finding peers"):
		return ClusterJoin, SevInfo, "entrypoint", "Finding peers", "", ""

	case strings.Contains(line, "Cluster address set to"):
		return ClusterBootstrap, SevInfo, "entrypoint", strings.TrimSpace(line), "", ""

	case strings.Contains(line, "Run setup: true"):
		return PMMSetupStarted, SevInfo, "pmm-agent", "PMM setup started", "", ""

	case strings.TrimSpace(line) == "Registered.":
		return PMMRegistered, SevInfo, "pmm-agent", "PMM agent registered", "", ""

	case strings.Contains(line, "Connected") && strings.Contains(line, "true"):
		return PMMConnected, SevInfo, "pmm-admin", "PMM client connected", "", ""

	case strings.Contains(line, "MySQL Service added"):
		return PMMServiceAdded, SevInfo, "pmm-admin", "MySQL service added", "", ""

	case strings.Contains(line, "AGENT_STATUS_RUNNING"):
		return ExporterStarted, SevInfo, "pmm-agent", "Exporter running", "", ""

	case strings.Contains(line, "Got SIGTERM"), strings.Contains(line, "Shutting down"), strings.Contains(line, "shutting down"):
		return Restart, SevWarning, "process", "SIGTERM / shutdown", "", ""

	case strings.Contains(line, "mysqld: Shutdown complete"):
		return Restart, SevInfo, "mysqld", "mysqld shutdown complete", "", ""
	}

	// Severity-only fallback.
	switch sev {
	case SevError:
		return Error, SevError, component, shortify(line, ""), "", ""
	case SevWarning:
		return Warning, SevWarning, component, shortify(line, ""), "", ""
	}
	return "", "", "", "", "", ""
}

func classifySeverity(line string) string {
	switch {
	case strings.Contains(line, "level=error"),
		strings.Contains(line, "[ERROR]"),
		strings.Contains(line, "[Error]"):
		return SevError
	case strings.Contains(line, "level=warning"),
		strings.Contains(line, "[Warning]"),
		strings.Contains(line, "[WARNING]"):
		return SevWarning
	case strings.Contains(line, "level=info"),
		strings.Contains(line, "[Note]"),
		strings.Contains(line, "[System]"),
		strings.Contains(line, "[Info]"):
		return SevInfo
	}
	return ""
}

func detectComponent(line string) string {
	switch {
	case strings.Contains(line, "[WSREP-SST]"):
		return "wsrep-sst"
	case strings.Contains(line, "[WSREP]"):
		return "wsrep"
	case strings.Contains(line, "[Galera]"):
		return "galera"
	case strings.Contains(line, "[InnoDB]"):
		return "innodb"
	case strings.Contains(line, "component=pmm-agent"), strings.Contains(line, "pmm-agent"):
		return "pmm-agent"
	case strings.Contains(line, "pmm-admin"):
		return "pmm-admin"
	case strings.Contains(line, "[Server]"):
		return "mysqld"
	}
	if i := strings.Index(line, "component="); i >= 0 {
		rest := line[i+len("component="):]
		end := strings.IndexAny(rest, " \t\"")
		if end > 0 {
			return rest[:end]
		}
	}
	return ""
}

var stateChangeRe = regexp.MustCompile(`Server status change (\w+) -> (\w+)`)

func parseStateChange(line string) (old, neu string) {
	if m := stateChangeRe.FindStringSubmatch(line); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// --- helpers ---

func splitLines(s string) []string {
	// Avoid producing a trailing empty element when the file ends with "\n".
	if s == "" {
		return nil
	}
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// shortify returns a single-line, length-capped summary of a log line.
// If marker is non-empty and present, the result ends at the marker phrase.
func shortify(line, marker string) string {
	line = strings.TrimSpace(line)
	if marker != "" {
		if i := strings.Index(line, marker); i >= 0 {
			line = line[:i+len(marker)]
		}
	}
	// Drop leading timestamps + bracketed prefixes so summaries are readable.
	if i := strings.Index(line, "msg=\""); i >= 0 {
		rest := line[i+len("msg=\""):]
		if j := strings.Index(rest, "\""); j > 0 {
			return truncate(rest[:j], 220)
		}
	}
	return truncate(line, 220)
}
