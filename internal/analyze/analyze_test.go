package analyze

import (
	"strings"
	"testing"

	"github.com/db-k8s/db-k8s/internal/db"
)

// runRulesOn decodes raw YAML and runs the dispatcher on every flattened doc.
// It does not use a real db.DB — analyzeFile is decoupled from the database.
func runRulesOn(t *testing.T, raw string) (string, []Finding) {
	t.Helper()
	f := db.File{ID: 42, DumpID: 7, FileKind: "yaml"}
	return analyzeFile(f, []byte(raw))
}

func contains(fs []Finding, rule string) (Finding, bool) {
	for _, f := range fs {
		if f.Rule == rule {
			return f, true
		}
	}
	return Finding{}, false
}

// ---------- Core Kubernetes rules ----------

func TestPodFailed(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: Pod
metadata: {name: bad, namespace: ns}
status:
  phase: Failed
  reason: PodFailed
  message: container crashed
`)
	f, ok := contains(fs, "pod.failed")
	if !ok {
		t.Fatalf("want pod.failed, got %v", fs)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("want critical, got %s", f.Severity)
	}
}

func TestPodCrashloop(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ns}
status:
  phase: Running
  containerStatuses:
  - name: app
    restartCount: 7
    state:
      waiting:
        reason: CrashLoopBackOff
    lastState:
      terminated:
        reason: Error
        exitCode: 1
`)
	f, ok := contains(fs, "pod.crashloop")
	if !ok {
		t.Fatalf("want pod.crashloop, got %v", fs)
	}
	if f.Fields["waiting.reason"] != "CrashLoopBackOff" {
		t.Errorf("missing waiting.reason: %v", f.Fields)
	}
	// restarts_high should also fire (rc=7 >= 5).
	if _, ok := contains(fs, "pod.restarts_high"); !ok {
		t.Errorf("expected pod.restarts_high to also fire with rc=7")
	}
}

func TestPodOOMKilled(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ns}
status:
  phase: Running
  containerStatuses:
  - name: app
    restartCount: 3
    lastState:
      terminated:
        reason: OOMKilled
        exitCode: 137
`)
	if _, ok := contains(fs, "pod.oomkilled"); !ok {
		t.Fatalf("want pod.oomkilled, got %v", fs)
	}
}

func TestPodNotReady(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ns}
status:
  phase: Running
  conditions:
  - type: Ready
    status: "False"
    reason: ContainersNotReady
    message: containers with unready status [app]
`)
	if _, ok := contains(fs, "pod.not_ready"); !ok {
		t.Fatalf("want pod.not_ready, got %v", fs)
	}
}

func TestEventWarningAggregation(t *testing.T) {
	// Three identical-reason Warning events should collapse into one finding.
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: List
items:
- {apiVersion: v1, kind: Event, type: Warning, reason: FailedScheduling, message: "no nodes", involvedObject: {kind: Pod, name: a}, metadata: {namespace: ns}}
- {apiVersion: v1, kind: Event, type: Warning, reason: FailedScheduling, message: "no nodes", involvedObject: {kind: Pod, name: a}, metadata: {namespace: ns}}
- {apiVersion: v1, kind: Event, type: Warning, reason: FailedScheduling, message: "no nodes", involvedObject: {kind: Pod, name: a}, metadata: {namespace: ns}}
`)
	count := 0
	for _, f := range fs {
		if f.Rule == "event.warning" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want 1 aggregated event.warning, got %d (%v)", count, fs)
	}
}

func TestDeploymentReplicasMismatch(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: ns}
spec:
  replicas: 3
status:
  availableReplicas: 1
`)
	if _, ok := contains(fs, "deployment.replicas_mismatch"); !ok {
		t.Fatalf("want deployment.replicas_mismatch, got %v", fs)
	}
}

func TestPVCPending(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data, namespace: ns}
status: {phase: Pending}
`)
	if _, ok := contains(fs, "pvc.pending"); !ok {
		t.Fatalf("want pvc.pending, got %v", fs)
	}
}

func TestNodeNotReady(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: v1
kind: Node
metadata: {name: n1}
status:
  conditions:
  - type: Ready
    status: "False"
  - type: MemoryPressure
    status: "True"
`)
	f, ok := contains(fs, "node.not_ready")
	if !ok {
		t.Fatalf("want node.not_ready, got %v", fs)
	}
	if !strings.Contains(f.Title, "Ready") || !strings.Contains(f.Title, "MemoryPressure") {
		t.Errorf("title should mention failing conditions: %q", f.Title)
	}
}

func TestRBACWildcard(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules:
- verbs: ["*"]
  resources: ["*"]
  apiGroups: ["*"]
`)
	if _, ok := contains(fs, "rbac.wildcard"); !ok {
		t.Fatalf("want rbac.wildcard, got %v", fs)
	}
}

// ---------- Percona shared rules ----------

func TestPerconaStateInitializing(t *testing.T) {
	// Mirrors samples/1 mysql-dnb.
	_, fs := runRulesOn(t, `
apiVersion: pxc.percona.com/v1
kind: PerconaXtraDBCluster
metadata: {name: mysql-dnb, namespace: everest}
status:
  state: initializing
  ready: 0
  size: 6
  message: "pxc: back-off 5m0s restarting failed container=pxc pod=mysql-dnb-pxc-0_everest"
`)
	f, ok := contains(fs, "percona.state_initializing")
	if !ok {
		t.Fatalf("want percona.state_initializing, got %v", fs)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("want critical, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "0/6") {
		t.Errorf("title should show ready/size: %q", f.Title)
	}
}

func TestPerconaStateError(t *testing.T) {
	// Mirrors samples/8 mysql-u94.
	_, fs := runRulesOn(t, `
apiVersion: pxc.percona.com/v1
kind: PerconaXtraDBCluster
metadata: {name: mysql-u94, namespace: everest}
status:
  state: error
  message: "manage sys users: monitor user grant system privilege"
`)
	if _, ok := contains(fs, "percona.state_error"); !ok {
		t.Fatalf("want percona.state_error, got %v", fs)
	}
}

func TestPerconaConditionFalsePGBackRest(t *testing.T) {
	// Mirrors samples/4 postgresql-zlp PGBackRestRepoHostReady=False.
	_, fs := runRulesOn(t, `
apiVersion: pgv2.percona.com/v2
kind: PerconaPGCluster
metadata: {name: postgresql-zlp, namespace: everest}
status:
  state: ready
  conditions:
  - type: PGBackRestRepoHostReady
    status: "False"
    reason: PGBackRestRepoHostReady
    message: ""
`)
	f, ok := contains(fs, "percona.condition_false")
	if !ok {
		t.Fatalf("want percona.condition_false, got %v", fs)
	}
	// Backup/repo failure should be elevated to critical.
	if f.Severity != SeverityCritical {
		t.Errorf("want critical for backup/repo, got %s", f.Severity)
	}
}

func TestPerconaConditionFalsePaused(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: pgv2.percona.com/v2
kind: PerconaPGCluster
metadata: {name: postgresql-awn, namespace: everest}
status:
  state: ready
  conditions:
  - type: Paused
    status: "False"
    reason: Paused
    message: "Reconciliation is paused"
`)
	f, ok := contains(fs, "percona.condition_false")
	if !ok {
		t.Fatalf("want percona.condition_false, got %v", fs)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("Paused should be info severity, got %s", f.Severity)
	}
}

func TestPSMDBHealthyHasNoFindings(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: psmdb.percona.com/v1
kind: PerconaServerMongoDB
metadata: {name: mongodb-rnp, namespace: everest}
status:
  state: ready
  ready: 12
  size: 12
  replsets:
  - {name: rs0, ready: 3, size: 3, status: ready, members: [
      {name: a, state: 1}, {name: b, state: 2}, {name: c, state: 2}]}
  mongos: {ready: 3, size: 3, status: ready}
`)
	for _, f := range fs {
		if strings.HasPrefix(f.Rule, "percona.") || strings.HasPrefix(f.Rule, "psmdb.") {
			t.Errorf("healthy cluster should not produce %s: %+v", f.Rule, f)
		}
	}
}

func TestPSMDBMemberDown(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: psmdb.percona.com/v1
kind: PerconaServerMongoDB
metadata: {name: mongodb-bad, namespace: everest}
status:
  state: ready
  replsets:
  - name: rs0
    ready: 2
    size: 3
    members:
    - {name: a, state: 1}
    - {name: b, state: 8}
    - {name: c, state: 2}
`)
	if _, ok := contains(fs, "psmdb.member_down"); !ok {
		t.Fatalf("want psmdb.member_down for state=8, got %v", fs)
	}
}

func TestPXCComponentUnhealthy(t *testing.T) {
	_, fs := runRulesOn(t, `
apiVersion: pxc.percona.com/v1
kind: PerconaXtraDBCluster
metadata: {name: c, namespace: everest}
status:
  state: initializing
  ready: 0
  size: 6
  pxc: {status: initializing, ready: 0, size: 3}
  haproxy: {status: ready, ready: 3, size: 3}
`)
	if _, ok := contains(fs, "pxc.component_unhealthy"); !ok {
		t.Fatalf("want pxc.component_unhealthy for pxc subcomp, got %v", fs)
	}
}

// ---------- File-level summary ----------

func TestFileSummaryPods(t *testing.T) {
	summary, _ := runRulesOn(t, `
apiVersion: v1
kind: List
items:
- {kind: Pod, status: {phase: Running}}
- {kind: Pod, status: {phase: Running}}
- {kind: Pod, status: {phase: Failed}}
`)
	if !strings.Contains(summary, "3 Pods") {
		t.Errorf("want '3 Pods' in summary, got %q", summary)
	}
	if !strings.Contains(summary, "2 Running") || !strings.Contains(summary, "1 Failed") {
		t.Errorf("want phase counts, got %q", summary)
	}
}

func TestFileSummaryPXC(t *testing.T) {
	summary, _ := runRulesOn(t, `
apiVersion: v1
kind: List
items:
- {kind: PerconaXtraDBCluster, metadata: {name: a}, status: {state: ready}}
- {kind: PerconaXtraDBCluster, metadata: {name: b}, status: {state: initializing}}
`)
	if !strings.Contains(summary, "2 PerconaXtraDBCluster") {
		t.Errorf("want summary header, got %q", summary)
	}
	if !strings.Contains(summary, "1 ready") || !strings.Contains(summary, "1 initializing") {
		t.Errorf("want state breakdown, got %q", summary)
	}
}

// ---------- Investigate helper ----------

func TestInvestigatePerconaIncludesContextNoSecrets(t *testing.T) {
	f := Finding{
		Severity: SeverityCritical, Rule: "percona.state_initializing",
		Kind: "PerconaXtraDBCluster", APIVersion: "pxc.percona.com/v1",
		Namespace: "everest", Name: "mysql-dnb",
		Fields: map[string]string{
			"status.state":   "initializing",
			"status.ready":   "0",
			"status.size":    "6",
			"status.message": "pxc: back-off 5m0s restarting failed container=pxc pod=mysql-dnb-pxc-0",
			// Sentinel "secret" that MUST NOT leak — investigate must ignore unknown keys.
			"data.password": "hunter2",
		},
	}
	prompt, gurl := Investigate(f)
	if !strings.Contains(prompt, "mysql-dnb") || !strings.Contains(prompt, "initializing") {
		t.Errorf("prompt missing core context: %q", prompt)
	}
	if !strings.Contains(prompt, "0") || !strings.Contains(prompt, "6") {
		t.Errorf("prompt missing ready/size: %q", prompt)
	}
	if strings.Contains(prompt, "hunter2") || strings.Contains(prompt, "data.password") {
		t.Errorf("prompt leaked unknown field: %q", prompt)
	}
	if !strings.HasPrefix(gurl, "https://www.google.com/search?q=") {
		t.Errorf("bad google url: %q", gurl)
	}
	if !strings.Contains(gurl, "PerconaXtraDBCluster") {
		t.Errorf("google url should mention kind: %q", gurl)
	}
}

func TestInvestigatePodCrashloop(t *testing.T) {
	f := Finding{
		Severity: SeverityCritical, Rule: "pod.crashloop",
		Kind: "Pod", Namespace: "ns", Name: "app-0",
		Fields: map[string]string{
			"container":     "app",
			"waiting.reason": "CrashLoopBackOff",
			"restartCount":  "7",
		},
	}
	prompt, gurl := Investigate(f)
	if !strings.Contains(prompt, "CrashLoopBackOff") {
		t.Errorf("prompt missing waiting.reason: %q", prompt)
	}
	if !strings.Contains(gurl, "CrashLoopBackOff") {
		t.Errorf("google url missing reason: %q", gurl)
	}
}

func TestInvestigateNeverEmpty(t *testing.T) {
	// Every rule should produce a non-empty prompt and URL.
	for _, rule := range []string{
		"pod.failed", "pod.crashloop", "pod.oomkilled", "pod.restarts_high", "pod.not_ready",
		"event.warning", "deployment.replicas_mismatch", "pvc.pending", "node.not_ready",
		"rbac.wildcard",
		"percona.state_error", "percona.state_initializing", "percona.state_other",
		"percona.replica_mismatch", "percona.message_present", "percona.condition_false",
		"pxc.component_unhealthy",
		"psmdb.replset_unhealthy", "psmdb.member_down", "psmdb.mongos_unhealthy",
		"pg.instance_unhealthy",
	} {
		f := Finding{Rule: rule, Kind: "Whatever", Fields: map[string]string{}}
		p, g := Investigate(f)
		if p == "" {
			t.Errorf("%s produced empty prompt", rule)
		}
		if !strings.HasPrefix(g, "https://www.google.com/") {
			t.Errorf("%s produced bad google url: %q", rule, g)
		}
	}
}
