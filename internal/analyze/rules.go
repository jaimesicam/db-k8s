package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/db-k8s/db-k8s/internal/db"
)

// dispatch routes one object to the appropriate rule functions based on its kind.
func dispatch(f db.File, doc map[string]any) []Finding {
	kind := str(doc, "kind")
	apiVer := str(doc, "apiVersion")
	name := str(doc, "metadata", "name")
	ns := str(doc, "metadata", "namespace")

	ctx := ruleCtx{
		f:      f,
		doc:    doc,
		kind:   kind,
		apiVer: apiVer,
		name:   name,
		ns:     ns,
	}

	switch kind {
	case "Pod":
		return runRules(ctx, podFailed, podCrashloop, podOOMKilled, podRestartsHigh, podNotReady)
	case "Event":
		return runRules(ctx, eventWarning)
	case "Deployment", "StatefulSet", "ReplicaSet":
		return runRules(ctx, deploymentReplicasMismatch)
	case "PersistentVolumeClaim":
		return runRules(ctx, pvcPending)
	case "Node":
		return runRules(ctx, nodeNotReady)
	case "ClusterRole", "Role":
		return runRules(ctx, rbacWildcard)
	case "PerconaXtraDBCluster", "PerconaServerMongoDB", "PerconaPGCluster":
		out := runRules(ctx,
			perconaStateError, perconaStateInitializing, perconaStateOther,
			perconaReplicaMismatch, perconaMessagePresent, perconaConditionFalse,
		)
		switch kind {
		case "PerconaXtraDBCluster":
			out = append(out, runRules(ctx, pxcComponentUnhealthy)...)
		case "PerconaServerMongoDB":
			out = append(out, runRules(ctx,
				psmdbReplsetUnhealthy, psmdbMemberDown, psmdbMongosUnhealthy)...)
		case "PerconaPGCluster":
			out = append(out, runRules(ctx, pgInstanceUnhealthy)...)
		}
		return out
	}
	return nil
}

type ruleCtx struct {
	f      db.File
	doc    map[string]any
	kind   string
	apiVer string
	name   string
	ns     string
}

type rule func(ctx ruleCtx) []Finding

func runRules(ctx ruleCtx, rs ...rule) []Finding {
	var out []Finding
	for _, r := range rs {
		out = append(out, r(ctx)...)
	}
	return out
}

func (c ruleCtx) finding(rule string, sev Severity, title, detail string, fields ...kv) Finding {
	f := Finding{
		Severity:   sev,
		Rule:       rule,
		Title:      title,
		Detail:     detail,
		DumpID:     c.f.DumpID,
		FileID:     c.f.ID,
		APIVersion: c.apiVer,
		Kind:       c.kind,
		Namespace:  c.ns,
		Name:       c.name,
		Fields:     map[string]string{},
	}
	for _, p := range fields {
		if p.v != "" {
			f.Fields[p.k] = p.v
		}
	}
	return f
}

type kv struct{ k, v string }

// ---------- Pod rules ----------

func podFailed(c ruleCtx) []Finding {
	phase := str(c.doc, "status", "phase")
	if phase == "Failed" || phase == "Unknown" {
		return []Finding{c.finding("pod.failed", SeverityCritical,
			fmt.Sprintf("Pod %s/%s is %s", c.ns, c.name, phase),
			fmt.Sprintf("status.phase = %s; reason = %s; message = %s",
				phase, str(c.doc, "status", "reason"), str(c.doc, "status", "message")),
			kv{"status.phase", phase},
			kv{"status.reason", str(c.doc, "status", "reason")},
			kv{"status.message", str(c.doc, "status", "message")},
		)}
	}
	return nil
}

func podCrashloop(c ruleCtx) []Finding {
	containers := containerStatuses(c.doc)
	var out []Finding
	for _, cs := range containers {
		reason := str(cs, "state", "waiting", "reason")
		if reason == "CrashLoopBackOff" || reason == "ImagePullBackOff" || reason == "ErrImagePull" {
			lastReason := str(cs, "lastState", "terminated", "reason")
			exit := numOrEmpty(cs, "lastState", "terminated", "exitCode")
			restarts := numOrEmpty(cs, "restartCount")
			out = append(out, c.finding("pod.crashloop", SeverityCritical,
				fmt.Sprintf("Container %s in %s/%s: %s",
					str(cs, "name"), c.ns, c.name, reason),
				fmt.Sprintf("waiting.reason = %s; lastState.terminated.reason = %s; exitCode = %s; restartCount = %s",
					reason, lastReason, exit, restarts),
				kv{"container", str(cs, "name")},
				kv{"waiting.reason", reason},
				kv{"lastState.terminated.reason", lastReason},
				kv{"lastState.terminated.exitCode", exit},
				kv{"restartCount", restarts},
			))
		}
	}
	return out
}

func podOOMKilled(c ruleCtx) []Finding {
	containers := containerStatuses(c.doc)
	var out []Finding
	for _, cs := range containers {
		if str(cs, "lastState", "terminated", "reason") == "OOMKilled" {
			out = append(out, c.finding("pod.oomkilled", SeverityCritical,
				fmt.Sprintf("Container %s in %s/%s was OOMKilled",
					str(cs, "name"), c.ns, c.name),
				fmt.Sprintf("lastState.terminated.reason = OOMKilled; restartCount = %s",
					numOrEmpty(cs, "restartCount")),
				kv{"container", str(cs, "name")},
				kv{"lastState.terminated.reason", "OOMKilled"},
				kv{"restartCount", numOrEmpty(cs, "restartCount")},
			))
		}
	}
	return out
}

func podRestartsHigh(c ruleCtx) []Finding {
	const threshold = 5
	containers := containerStatuses(c.doc)
	var out []Finding
	for _, cs := range containers {
		rc := numI64(cs, "restartCount")
		if rc >= threshold {
			out = append(out, c.finding("pod.restarts_high", SeverityWarning,
				fmt.Sprintf("Container %s in %s/%s has %d restarts",
					str(cs, "name"), c.ns, c.name, rc),
				fmt.Sprintf("restartCount = %d (threshold %d)", rc, threshold),
				kv{"container", str(cs, "name")},
				kv{"restartCount", fmt.Sprint(rc)},
			))
		}
	}
	return out
}

func podNotReady(c ruleCtx) []Finding {
	// Only flag if phase is Running but Ready=False (i.e. running but unhealthy);
	// Failed/Pending are covered elsewhere.
	phase := str(c.doc, "status", "phase")
	if phase != "Running" {
		return nil
	}
	conds, _ := c.doc["status"].(map[string]any)
	if conds == nil {
		return nil
	}
	for _, cond := range slice(conds, "conditions") {
		if str(cond, "type") == "Ready" && str(cond, "status") == "False" {
			return []Finding{c.finding("pod.not_ready", SeverityWarning,
				fmt.Sprintf("Pod %s/%s is Running but not Ready", c.ns, c.name),
				fmt.Sprintf("Ready condition: status = False; reason = %s; message = %s",
					str(cond, "reason"), str(cond, "message")),
				kv{"status.phase", phase},
				kv{"condition.Ready.reason", str(cond, "reason")},
				kv{"condition.Ready.message", str(cond, "message")},
			)}
		}
	}
	return nil
}

func containerStatuses(pod map[string]any) []map[string]any {
	status, _ := pod["status"].(map[string]any)
	if status == nil {
		return nil
	}
	var out []map[string]any
	for _, key := range []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"} {
		for _, c := range slice(status, key) {
			out = append(out, c)
		}
	}
	return out
}

// ---------- Event rules ----------

func eventWarning(c ruleCtx) []Finding {
	if str(c.doc, "type") != "Warning" {
		return nil
	}
	reason := str(c.doc, "reason")
	involvedKind := str(c.doc, "involvedObject", "kind")
	involvedName := str(c.doc, "involvedObject", "name")
	return []Finding{c.finding("event.warning", SeverityWarning,
		fmt.Sprintf("Warning event: %s on %s/%s", reason, involvedKind, involvedName),
		str(c.doc, "message"),
		kv{"reason", reason},
		kv{"involvedObject.kind", involvedKind},
		kv{"involvedObject.name", involvedName},
		kv{"message", str(c.doc, "message")},
	)}
}

// aggregateEvents collapses many event.warning findings into one per (involvedKind, reason).
// We keep the most recent example's message as the Detail.
func aggregateEvents(fs []Finding) []Finding {
	type bucket struct {
		example Finding
		count   int
	}
	buckets := map[string]*bucket{}
	var others []Finding
	for _, f := range fs {
		if f.Rule != "event.warning" {
			others = append(others, f)
			continue
		}
		key := f.Fields["involvedObject.kind"] + "|" + f.Fields["reason"] + "|" + f.Namespace
		b, ok := buckets[key]
		if !ok {
			buckets[key] = &bucket{example: f, count: 1}
			continue
		}
		b.count++
	}
	for _, b := range buckets {
		f := b.example
		if b.count > 1 {
			f.Title = fmt.Sprintf("%s (%d events)", f.Title, b.count)
			f.Fields["count"] = fmt.Sprint(b.count)
		}
		others = append(others, f)
	}
	return others
}

// ---------- Deployment / StatefulSet / ReplicaSet rules ----------

func deploymentReplicasMismatch(c ruleCtx) []Finding {
	desired := numI64(c.doc, "spec", "replicas")
	available := numI64(c.doc, "status", "availableReplicas")
	if desired > 0 && available < desired {
		return []Finding{c.finding("deployment.replicas_mismatch", SeverityWarning,
			fmt.Sprintf("%s %s/%s has %d/%d available replicas",
				c.kind, c.ns, c.name, available, desired),
			fmt.Sprintf("spec.replicas = %d; status.availableReplicas = %d", desired, available),
			kv{"spec.replicas", fmt.Sprint(desired)},
			kv{"status.availableReplicas", fmt.Sprint(available)},
		)}
	}
	return nil
}

// ---------- PVC rules ----------

func pvcPending(c ruleCtx) []Finding {
	phase := str(c.doc, "status", "phase")
	if phase != "" && phase != "Bound" {
		return []Finding{c.finding("pvc.pending", SeverityWarning,
			fmt.Sprintf("PVC %s/%s is %s", c.ns, c.name, phase),
			fmt.Sprintf("status.phase = %s", phase),
			kv{"status.phase", phase},
		)}
	}
	return nil
}

// ---------- Node rules ----------

func nodeNotReady(c ruleCtx) []Finding {
	conds, _ := c.doc["status"].(map[string]any)
	if conds == nil {
		return nil
	}
	var problems []string
	fields := []kv{}
	for _, cond := range slice(conds, "conditions") {
		t := str(cond, "type")
		s := str(cond, "status")
		switch t {
		case "Ready":
			if s != "True" {
				problems = append(problems, fmt.Sprintf("Ready=%s", s))
				fields = append(fields, kv{"condition.Ready", s})
			}
		case "MemoryPressure", "DiskPressure", "PIDPressure":
			if s == "True" {
				problems = append(problems, fmt.Sprintf("%s=True", t))
				fields = append(fields, kv{"condition." + t, s})
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return []Finding{c.finding("node.not_ready", SeverityCritical,
		fmt.Sprintf("Node %s: %s", c.name, strings.Join(problems, ", ")),
		strings.Join(problems, "; "),
		fields...,
	)}
}

func nodeIsReady(node map[string]any) bool {
	status, _ := node["status"].(map[string]any)
	if status == nil {
		return true
	}
	for _, cond := range slice(status, "conditions") {
		if str(cond, "type") == "Ready" {
			return str(cond, "status") == "True"
		}
	}
	return true
}

// ---------- RBAC rules ----------

func rbacWildcard(c ruleCtx) []Finding {
	for _, r := range slice(c.doc, "rules") {
		if hasWildcardStr(strSlice(r, "verbs")) && hasWildcardStr(strSlice(r, "resources")) {
			return []Finding{c.finding("rbac.wildcard", SeverityInfo,
				fmt.Sprintf("%s %s grants wildcard access", c.kind, displayName(c)),
				"At least one rule has verbs=[*] AND resources=[*]",
			)}
		}
	}
	return nil
}

func hasWildcardStr(items []string) bool {
	for _, s := range items {
		if s == "*" {
			return true
		}
	}
	return false
}

// strSlice extracts a []string at the given path (e.g. verbs or resources).
func strSlice(m map[string]any, path ...string) []string {
	v := walkAny(m, path...)
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func walkAny(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[p]
	}
	return cur
}

// ---------- Percona shared rules ----------

func perconaStateError(c ruleCtx) []Finding {
	state := str(c.doc, "status", "state")
	if state != "error" {
		return nil
	}
	msg := str(c.doc, "status", "message")
	return []Finding{c.finding("percona.state_error", SeverityCritical,
		fmt.Sprintf("%s %s/%s is in state=error", c.kind, c.ns, c.name),
		ifEmpty(msg, "status.state = error"),
		kv{"status.state", state},
		kv{"status.message", msg},
	)}
}

func perconaStateInitializing(c ruleCtx) []Finding {
	state := str(c.doc, "status", "state")
	if state != "initializing" {
		return nil
	}
	ready := numI64(c.doc, "status", "ready")
	size := numI64(c.doc, "status", "size")
	if ready >= size && size > 0 {
		return nil
	}
	msg := str(c.doc, "status", "message")
	return []Finding{c.finding("percona.state_initializing", SeverityCritical,
		fmt.Sprintf("%s %s/%s is initializing (%d/%d ready)", c.kind, c.ns, c.name, ready, size),
		ifEmpty(msg, fmt.Sprintf("status.state = initializing; ready %d/%d", ready, size)),
		kv{"status.state", state},
		kv{"status.ready", fmt.Sprint(ready)},
		kv{"status.size", fmt.Sprint(size)},
		kv{"status.message", msg},
	)}
}

func perconaStateOther(c ruleCtx) []Finding {
	state := str(c.doc, "status", "state")
	switch state {
	case "", "ready", "error", "initializing":
		return nil
	}
	return []Finding{c.finding("percona.state_other", SeverityWarning,
		fmt.Sprintf("%s %s/%s state = %s", c.kind, c.ns, c.name, state),
		fmt.Sprintf("status.state = %s", state),
		kv{"status.state", state},
	)}
}

func perconaReplicaMismatch(c ruleCtx) []Finding {
	ready := numI64(c.doc, "status", "ready")
	size := numI64(c.doc, "status", "size")
	state := str(c.doc, "status", "state")
	// Only fire when overall state appears healthy but counts still disagree —
	// otherwise the state_* rules already cover it.
	if state != "ready" || size == 0 || ready == size {
		return nil
	}
	return []Finding{c.finding("percona.replica_mismatch", SeverityWarning,
		fmt.Sprintf("%s %s/%s ready=%d != size=%d", c.kind, c.ns, c.name, ready, size),
		fmt.Sprintf("status.ready = %d; status.size = %d", ready, size),
		kv{"status.ready", fmt.Sprint(ready)},
		kv{"status.size", fmt.Sprint(size)},
	)}
}

func perconaMessagePresent(c ruleCtx) []Finding {
	msg := str(c.doc, "status", "message")
	state := str(c.doc, "status", "state")
	if msg == "" {
		return nil
	}
	// Don't duplicate when state_error/state_initializing already reports the message.
	if state == "error" || state == "initializing" {
		return nil
	}
	return []Finding{c.finding("percona.message_present", SeverityWarning,
		fmt.Sprintf("%s %s/%s reports a status message", c.kind, c.ns, c.name),
		msg,
		kv{"status.message", msg},
		kv{"status.state", state},
	)}
}

// perconaConditionFalse walks status.conditions[] and emits one finding per failing condition.
// Severity scales by reason: backup/repo failures are critical, Paused is info, the rest warning.
func perconaConditionFalse(c ruleCtx) []Finding {
	conds := slice(c.doc, "status", "conditions")
	var out []Finding
	for _, cond := range conds {
		if str(cond, "status") != "False" {
			continue
		}
		t := str(cond, "type")
		reason := str(cond, "reason")
		message := str(cond, "message")
		sev := SeverityWarning
		low := strings.ToLower(t + " " + reason)
		switch {
		case strings.Contains(low, "backup"), strings.Contains(low, "repo"),
			strings.Contains(low, "pgbackrest"):
			sev = SeverityCritical
		case strings.Contains(low, "paused"):
			sev = SeverityInfo
		}
		out = append(out, c.finding("percona.condition_false", sev,
			fmt.Sprintf("%s %s/%s: condition %s = False", c.kind, c.ns, c.name, t),
			ifEmpty(message, fmt.Sprintf("reason = %s", reason)),
			kv{"condition.type", t},
			kv{"condition.reason", reason},
			kv{"condition.message", message},
		))
	}
	return out
}

// ---------- PXC sub-component rules ----------

func pxcComponentUnhealthy(c ruleCtx) []Finding {
	var out []Finding
	for _, comp := range []string{"pxc", "haproxy", "proxysql"} {
		statusObj, ok := walkAny(c.doc, "status", comp).(map[string]any)
		if !ok {
			continue
		}
		st := str(statusObj, "status")
		if st == "" || st == "ready" {
			continue
		}
		ready := numI64(statusObj, "ready")
		size := numI64(statusObj, "size")
		out = append(out, c.finding("pxc.component_unhealthy", SeverityWarning,
			fmt.Sprintf("%s %s/%s: %s component is %s (%d/%d)",
				c.kind, c.ns, c.name, comp, st, ready, size),
			fmt.Sprintf("status.%s.status = %s; ready %d/%d", comp, st, ready, size),
			kv{"component", comp},
			kv{"component.status", st},
			kv{"component.ready", fmt.Sprint(ready)},
			kv{"component.size", fmt.Sprint(size)},
		))
	}
	return out
}

// ---------- PSMDB sub-component rules ----------

func psmdbReplsetUnhealthy(c ruleCtx) []Finding {
	var out []Finding
	for _, rs := range slice(c.doc, "status", "replsets") {
		name := str(rs, "name")
		status := str(rs, "status")
		ready := numI64(rs, "ready")
		size := numI64(rs, "size")
		if status != "" && status != "ready" {
			out = append(out, c.finding("psmdb.replset_unhealthy", SeverityWarning,
				fmt.Sprintf("PSMDB %s/%s replset %s is %s", c.ns, c.name, name, status),
				fmt.Sprintf("status = %s; ready %d/%d", status, ready, size),
				kv{"replset", name},
				kv{"replset.status", status},
				kv{"replset.ready", fmt.Sprint(ready)},
				kv{"replset.size", fmt.Sprint(size)},
			))
		} else if size > 0 && ready != size {
			out = append(out, c.finding("psmdb.replset_unhealthy", SeverityWarning,
				fmt.Sprintf("PSMDB %s/%s replset %s ready=%d != size=%d",
					c.ns, c.name, name, ready, size),
				fmt.Sprintf("ready %d/%d", ready, size),
				kv{"replset", name},
				kv{"replset.ready", fmt.Sprint(ready)},
				kv{"replset.size", fmt.Sprint(size)},
			))
		}
	}
	return out
}

func psmdbMemberDown(c ruleCtx) []Finding {
	// Healthy MongoDB member states: 1=PRIMARY, 2=SECONDARY, 7=ARBITER.
	var out []Finding
	for _, rs := range slice(c.doc, "status", "replsets") {
		rsName := str(rs, "name")
		for _, member := range slice(rs, "members") {
			state := numI64(member, "state")
			if state == 1 || state == 2 || state == 7 {
				continue
			}
			if state == 0 {
				// state field absent - skip (no signal)
				continue
			}
			out = append(out, c.finding("psmdb.member_down", SeverityCritical,
				fmt.Sprintf("PSMDB %s/%s replset %s: member %s state=%d",
					c.ns, c.name, rsName, str(member, "name"), state),
				fmt.Sprintf("member state %d is not PRIMARY/SECONDARY/ARBITER", state),
				kv{"replset", rsName},
				kv{"member", str(member, "name")},
				kv{"member.state", fmt.Sprint(state)},
			))
		}
	}
	return out
}

func psmdbMongosUnhealthy(c ruleCtx) []Finding {
	mongos, ok := walkAny(c.doc, "status", "mongos").(map[string]any)
	if !ok {
		return nil
	}
	st := str(mongos, "status")
	if st == "" || st == "ready" {
		return nil
	}
	return []Finding{c.finding("psmdb.mongos_unhealthy", SeverityWarning,
		fmt.Sprintf("PSMDB %s/%s mongos is %s", c.ns, c.name, st),
		fmt.Sprintf("status.mongos.status = %s; ready %d/%d", st,
			numI64(mongos, "ready"), numI64(mongos, "size")),
		kv{"mongos.status", st},
		kv{"mongos.ready", fmt.Sprint(numI64(mongos, "ready"))},
		kv{"mongos.size", fmt.Sprint(numI64(mongos, "size"))},
	)}
}

// ---------- PG sub-component rules ----------

func pgInstanceUnhealthy(c ruleCtx) []Finding {
	var out []Finding
	for _, set := range slice(c.doc, "status", "instances") {
		name := str(set, "name")
		ready := numI64(set, "ready")
		size := numI64(set, "size")
		if size > 0 && ready != size {
			out = append(out, c.finding("pg.instance_unhealthy", SeverityWarning,
				fmt.Sprintf("PG %s/%s instance set %s: ready=%d != size=%d",
					c.ns, c.name, name, ready, size),
				fmt.Sprintf("ready %d/%d", ready, size),
				kv{"instance_set", name},
				kv{"ready", fmt.Sprint(ready)},
				kv{"size", fmt.Sprint(size)},
			))
		}
	}
	// Sort deterministic.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Fields["instance_set"] < out[j].Fields["instance_set"] })
	return out
}

// ---------- helpers ----------

// str walks the doc by string keys and returns a string value at the leaf, or "".
func str(m map[string]any, path ...string) string {
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[p]
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
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

// numI64 returns an int64 value at the path, or 0.
func numI64(m map[string]any, path ...string) int64 {
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = obj[p]
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

func numOrEmpty(m map[string]any, path ...string) string {
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[p]
	}
	switch v := cur.(type) {
	case int:
		return fmt.Sprint(v)
	case int64:
		return fmt.Sprint(v)
	case float64:
		return fmt.Sprint(int64(v))
	case string:
		return v
	}
	return ""
}

// slice returns the array at the path as []map[string]any, dropping non-map entries.
func slice(m map[string]any, path ...string) []map[string]any {
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[p]
	}
	arr, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, x := range arr {
		if mm, ok := x.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func displayName(c ruleCtx) string {
	if c.ns == "" {
		return c.name
	}
	return c.ns + "/" + c.name
}
