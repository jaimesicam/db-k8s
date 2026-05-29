package pxc

import (
	"strings"
	"testing"
	"time"
)

// ---- timestamp parsing ----

func TestParseLogfmtTimestamp(t *testing.T) {
	line := `time="2026-05-28T12:51:45.934+00:00" level=info msg="hi"`
	ts, ok := parseTimestamp(line)
	if !ok {
		t.Fatalf("expected to parse timestamp from %q", line)
	}
	want := time.Date(2026, 5, 28, 12, 51, 45, 934_000_000, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("got %v, want %v", ts, want)
	}
}

func TestParseMySQLISOTimestamp(t *testing.T) {
	line := "2026-05-28T12:53:25.743853Z 0 [Note] [MY-000000] [Galera] SST sent"
	ts, ok := parseTimestamp(line)
	if !ok {
		t.Fatalf("expected to parse timestamp from %q", line)
	}
	if ts.Year() != 2026 || ts.Month() != 5 || ts.Day() != 28 || ts.Hour() != 12 || ts.Minute() != 53 {
		t.Errorf("unexpected timestamp: %v", ts)
	}
}

func TestParseSlashedTimestamp(t *testing.T) {
	line := "2026/05/28 12:51:46 Determined Domain to be everest.svc.cluster.local"
	ts, ok := parseTimestamp(line)
	if !ok || ts.Hour() != 12 || ts.Minute() != 51 {
		t.Errorf("slashed timestamp not parsed: ok=%v ts=%v", ok, ts)
	}
}

func TestNoTimestampReturnsFalse(t *testing.T) {
	if _, ok := parseTimestamp("Registered."); ok {
		t.Error("expected parseTimestamp to return false on a line with no timestamp")
	}
}

// ---- node identity ----

func TestNodeFromExplicitNodeName(t *testing.T) {
	if n := nodeFromExplicit("Node name: everest-mysql-mwl-pxc-0"); n != "everest-mysql-mwl-pxc-0" {
		t.Errorf("expected node name, got %q", n)
	}
	if n := nodeFromExplicit("Service name: everest-mysql-mwl-pxc-1"); n != "everest-mysql-mwl-pxc-1" {
		t.Errorf("expected service name match, got %q", n)
	}
	if n := nodeFromExplicit("just a regular line"); n != "" {
		t.Errorf("expected empty, got %q", n)
	}
}

func TestPXCNodeFromPath(t *testing.T) {
	cases := map[string]string{
		"cluster-dump/everest/mysql-mwl-pxc-0/logs.txt":  "mysql-mwl-pxc-0",
		"cluster-dump/everest/mysql-mwl-pxc-2/logs.txt":  "mysql-mwl-pxc-2",
		"foo/bar/c-pxc-12/logs.txt":                     "c-pxc-12",
		"cluster-dump/everest/mysql-mwl-haproxy-0/logs.txt": "",
		"cluster-dump/everest/pods.yaml":                  "",
	}
	for path, want := range cases {
		got, ok := PXCNodeFromPath(path)
		if want == "" {
			if ok {
				t.Errorf("%q: expected no match, got %q", path, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q: got %q ok=%v, want %q", path, got, ok, want)
		}
	}
}

// ---- event classification ----

func parseLine(t *testing.T, line string, pathNode string) Event {
	t.Helper()
	events := ParseFile(1, 1, pathNode, line)
	if len(events) != 1 {
		t.Fatalf("expected 1 event for %q, got %d: %+v", line, len(events), events)
	}
	return events[0]
}

func TestClassifyMySQLReady(t *testing.T) {
	ev := parseLine(t, "2026-05-28T12:51:51.702236Z 0 [System] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections. Version: '8.4.7-7.1'", "mysql-mwl-pxc-0")
	if ev.Type != MySQLReady {
		t.Errorf("want mysql_ready, got %s", ev.Type)
	}
	if ev.Node != "mysql-mwl-pxc-0" {
		t.Errorf("want path-derived node, got %s", ev.Node)
	}
}

func TestClassifyWSREPReady(t *testing.T) {
	ev := parseLine(t, "2026-05-28T12:51:51.720113Z 2 [Note] [MY-000000] [WSREP] Synchronized with group, ready for connections", "n0")
	if ev.Type != WSREPReady {
		t.Errorf("want wsrep_ready (Synchronized with group beats ready for connections), got %s", ev.Type)
	}
}

func TestClassifySSTCompleted(t *testing.T) {
	ev := parseLine(t, "2026-05-28T12:53:32.035766Z 3 [System] [MY-000000] [WSREP] SST completed", "n1")
	if ev.Type != SSTCompleted {
		t.Errorf("want sst_completed, got %s", ev.Type)
	}
}

func TestClassifySSTSent(t *testing.T) {
	ev := parseLine(t, "2026-05-28T12:53:25.736397Z 0 [Note] [MY-000000] [Galera] SST sent: fefd6023-5a93-11f1-9edc-5b519b19b4ed:33", "n0")
	if ev.Type != SSTSent {
		t.Errorf("want sst_sent, got %s", ev.Type)
	}
}

func TestClassifyServerStatusChangeDonorJoined(t *testing.T) {
	ev := parseLine(t, "2026-05-28T12:53:25.736429Z 0 [Note] [MY-000000] [WSREP] Server status change donor -> joined", "n0")
	if ev.Type != ServerStatusChange {
		t.Errorf("want server_status_change, got %s", ev.Type)
	}
	if ev.OldState != "donor" || ev.NewState != "joined" {
		t.Errorf("want donor→joined, got %s→%s", ev.OldState, ev.NewState)
	}
}

func TestClassifyPMMSetupAndRegistered(t *testing.T) {
	setup := parseLine(t, `time="2026-05-28T12:51:45.896+00:00" level=info msg="Run setup: true Sidecar mode: true" component=entrypoint`, "pxc-0")
	if setup.Type != PMMSetupStarted {
		t.Errorf("want pmm_setup_started, got %s", setup.Type)
	}
	reg := parseLine(t, "Registered.", "pxc-0")
	if reg.Type != PMMRegistered {
		t.Errorf("want pmm_registered, got %s", reg.Type)
	}
}

func TestClassifyPMMConnected(t *testing.T) {
	ev := parseLine(t, "\tConnected        : true", "pxc-0")
	if ev.Type != PMMConnected {
		t.Errorf("want pmm_connected, got %s", ev.Type)
	}
}

func TestClassifyPMMServiceAdded(t *testing.T) {
	ev := parseLine(t, "MySQL Service added.", "pxc-0")
	if ev.Type != PMMServiceAdded {
		t.Errorf("want pmm_service_added, got %s", ev.Type)
	}
}

func TestClassifyLogfmtWarningError(t *testing.T) {
	w := parseLine(t, `time="2026-05-28T12:51:45.922+00:00" level=warning msg="Got SIGTERM, shutting down..."`, "pxc-0")
	// SIGTERM line is matched explicitly as restart (warning severity), not generic warning.
	if w.Type != Restart && w.Type != Warning {
		t.Errorf("want restart or warning, got %s", w.Type)
	}
	e := parseLine(t, `time="2026-05-28T12:51:45.913+00:00" level=error msg="Agent ID is not provided, halting." component=client`, "pxc-0")
	if e.Type != Error {
		t.Errorf("want error, got %s", e.Type)
	}
}

func TestClassifyBracketedSeverity(t *testing.T) {
	w := parseLine(t, "2026-05-28T12:51:50.974364Z 0 [Warning] [MY-000000] [Galera] Could not open state file", "pxc-0")
	if w.Type != Warning {
		t.Errorf("want warning from [Warning], got %s", w.Type)
	}
}

// ---- chronological sort + missing-timestamp inheritance ----

func TestEventsSortedChronologically(t *testing.T) {
	content := strings.Join([]string{
		"2026-05-28T12:53:25.743853Z 2 [Note] [MY-000000] [WSREP] Synchronized with group, ready for connections",
		`time="2026-05-28T12:51:45.896+00:00" level=info msg="Run setup: true Sidecar mode: true" component=entrypoint`,
		"2026-05-28T12:51:51.720113Z 2 [Note] [MY-000000] [WSREP] Server status change joined -> synced",
	}, "\n")
	events := ParseFile(1, 1, "pxc-0", content)
	// ParseFile returns events in file order; the timeline aggregator sorts.
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	for _, e := range events {
		if e.FileID != 1 {
			t.Errorf("event missing file id: %+v", e)
		}
		if e.LineNumber <= 0 {
			t.Errorf("event missing line number: %+v", e)
		}
	}
}

func TestMissingTimestampInheritsPrevious(t *testing.T) {
	content := strings.Join([]string{
		`time="2026-05-28T12:51:45.896+00:00" level=info msg="Run setup: true Sidecar mode: true"`,
		"MySQL Service added.", // no timestamp on this line
	}, "\n")
	events := ParseFile(1, 1, "pxc-0", content)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1].HasTime {
		t.Error("expected the bare line to be marked as HasTime=false")
	}
	if !events[1].Timestamp.Equal(events[0].Timestamp) {
		t.Errorf("expected inherited timestamp, got %v vs %v", events[1].Timestamp, events[0].Timestamp)
	}
}

func TestEmptyContentReturnsNothing(t *testing.T) {
	if evs := ParseFile(1, 1, "n", ""); len(evs) != 0 {
		t.Errorf("expected no events for empty content, got %d", len(evs))
	}
}

// ---- analysis integration ----

func TestAnalyzeNodeSummaries(t *testing.T) {
	// Two synthetic files for two PXC nodes.
	// We exercise dumpAccum.add directly because Analyze requires a DB.
	a := &dumpAccum{dumpID: 7, nodes: map[string]*NodeSummary{}}
	for _, ev := range ParseFile(7, 10, "mysql-mwl-pxc-0", strings.Join([]string{
		"2026-05-28T12:51:51.702236Z 0 [System] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections.",
		"2026-05-28T12:51:51.720113Z 2 [Note] [MY-000000] [WSREP] Synchronized with group, ready for connections",
		"2026-05-28T12:53:10.211167Z 2 [Note] [MY-000000] [WSREP] Server status change synced -> donor",
		"2026-05-28T12:53:25.736397Z 0 [Note] [MY-000000] [Galera] SST sent: a:b",
	}, "\n")) {
		a.add(ev)
	}
	for _, ev := range ParseFile(7, 11, "mysql-mwl-pxc-1", strings.Join([]string{
		"2026-05-28T12:53:09.337226Z 1 [Note] [MY-000000] [WSREP] Server status change disconnected -> connected",
		"2026-05-28T12:53:09.343282Z 1 [Note] [MY-000000] [WSREP] Server status change connected -> joiner",
		"2026-05-28T12:53:32.035766Z 3 [System] [MY-000000] [WSREP] SST completed",
		"2026-05-28T12:53:32.042544Z 1 [Note] [MY-000000] [WSREP] Synchronized with group, ready for connections",
	}, "\n")) {
		a.add(ev)
	}
	dt := a.build()
	if len(dt.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %v", dt.Nodes)
	}
	n0 := dt.NodeSummaries["mysql-mwl-pxc-0"]
	if !n0.HasMySQLReady || !n0.HasWSREP || !n0.HasSST || !n0.ActedAsDonor {
		t.Errorf("pxc-0 missing milestones: %+v", n0)
	}
	n1 := dt.NodeSummaries["mysql-mwl-pxc-1"]
	if !n1.HasWSREP || !n1.HasSST || !n1.ActedAsJoiner {
		t.Errorf("pxc-1 missing milestones: %+v", n1)
	}
	if dt.SSTCount == 0 {
		t.Error("expected SSTCount > 0")
	}
	if dt.NodesMySQLReady == 0 {
		t.Error("expected at least one node MySQL-ready")
	}
}

// ---- timeline buckets ----

func TestBucketEventsGroupsBySecond(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(off time.Duration, node string) Event {
		return Event{Timestamp: t0.Add(off), HasTime: true, Node: node, Type: MySQLReady}
	}
	events := []Event{
		mk(0, "a"),
		mk(100*time.Millisecond, "b"),
		mk(2*time.Second, "a"),
	}
	buckets := bucketEvents(events)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
	if len(buckets[0].ByNode["a"]) != 1 || len(buckets[0].ByNode["b"]) != 1 {
		t.Errorf("bucket 0 should have both a and b: %+v", buckets[0].ByNode)
	}
}
