package analyze

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Investigate returns a copy-friendly AI prompt and a Google search URL for one finding.
// Both are derived from curated Finding fields only — never from the raw YAML BLOB.
// Secrets, ConfigMap data values, env vars, and image-pull secrets are never included.
func Investigate(f Finding) (prompt string, googleURL string) {
	return buildPrompt(f), buildGoogleURL(f)
}

func buildPrompt(f Finding) string {
	switch family(f.Rule) {
	case "percona":
		return perconaPrompt(f)
	case "pod":
		return podPrompt(f)
	case "event":
		return eventPrompt(f)
	case "node":
		return nodePrompt(f)
	case "deployment":
		return deploymentPrompt(f)
	case "pvc":
		return pvcPrompt(f)
	case "rbac":
		return rbacPrompt(f)
	}
	return genericPrompt(f)
}

func family(rule string) string {
	if i := strings.IndexByte(rule, '.'); i > 0 {
		switch rule[:i] {
		case "percona", "pxc", "psmdb", "pg":
			return "percona"
		case "pod":
			return "pod"
		case "event":
			return "event"
		case "node":
			return "node"
		case "deployment":
			return "deployment"
		case "pvc":
			return "pvc"
		case "rbac":
			return "rbac"
		}
	}
	return "generic"
}

func perconaPrompt(f Finding) string {
	kindLong := map[string]string{
		"PerconaXtraDBCluster": "Percona XtraDB Cluster",
		"PerconaServerMongoDB": "Percona Server for MongoDB cluster",
		"PerconaPGCluster":     "Percona PostgreSQL Cluster",
	}[f.Kind]
	if kindLong == "" {
		kindLong = f.Kind
	}
	var b strings.Builder
	fmt.Fprintf(&b, "I'm troubleshooting a %s running on Kubernetes.\n\n", kindLong)
	fmt.Fprintf(&b, "Cluster: %s (namespace: %s)\n", f.Name, f.Namespace)
	if f.APIVersion != "" {
		fmt.Fprintf(&b, "apiVersion: %s\n", f.APIVersion)
	}
	writeFields(&b, f, []string{
		"status.state", "status.ready", "status.size",
		"condition.type", "condition.reason", "condition.message",
		"component", "component.status", "component.ready", "component.size",
		"replset", "replset.status", "replset.ready", "replset.size",
		"member", "member.state",
		"mongos.status", "mongos.ready", "mongos.size",
		"instance_set",
		"status.message",
	})
	fmt.Fprintf(&b, "Detected rule: %s\n\n", f.Rule)
	b.WriteString(perconaQuestion(f))
	return b.String()
}

func perconaQuestion(f Finding) string {
	switch f.Rule {
	case "percona.state_error":
		return "What does this error state typically mean for this operator, what are the most common root causes, and what should I check next? Cite the relevant Percona docs if you can."
	case "percona.state_initializing":
		return "The cluster is stuck in 'initializing' rather than progressing to 'ready'. What are the most common causes (storage, container restarts, resource limits, certificates), and what should I check in the operator and pod logs?"
	case "percona.condition_false":
		return "What does this condition mean, what does it imply for cluster health, and what are the typical fixes? Anything I should grab from the operator logs?"
	case "pxc.component_unhealthy":
		return "Which component (pxc / haproxy / proxysql) is unhealthy and why does this typically happen? What's the right order to debug?"
	case "psmdb.replset_unhealthy", "psmdb.member_down", "psmdb.mongos_unhealthy":
		return "What does this replica-set / mongos state mean for a MongoDB cluster, what are the typical causes, and what mongosh / kubectl commands help diagnose it?"
	case "pg.instance_unhealthy":
		return "What does this instance-set state mean for a Percona PostgreSQL Cluster, and what should I check in the operator and Patroni logs?"
	case "percona.replica_mismatch":
		return "The cluster reports state=ready but ready != size. Is this a transient reconciliation lag or a real concern, and how do I tell which?"
	case "percona.message_present":
		return "What does this status.message typically indicate, and what's the right next step?"
	}
	return "What does this state mean, and what should I check next?"
}

func podPrompt(f Finding) string {
	var b strings.Builder
	b.WriteString("I'm troubleshooting a Kubernetes Pod issue.\n\n")
	fmt.Fprintf(&b, "Pod: %s (namespace: %s)\n", f.Name, f.Namespace)
	writeFields(&b, f, []string{
		"status.phase", "status.reason", "status.message",
		"container", "waiting.reason",
		"lastState.terminated.reason", "lastState.terminated.exitCode",
		"restartCount",
		"condition.Ready.reason", "condition.Ready.message",
	})
	fmt.Fprintf(&b, "Detected rule: %s\n\n", f.Rule)
	switch f.Rule {
	case "pod.crashloop":
		b.WriteString("What are the typical root causes for a container in CrashLoopBackOff / ImagePullBackOff, and what should I look for in the container logs and `kubectl describe pod` output?")
	case "pod.oomkilled":
		b.WriteString("The container was OOMKilled. What does this imply about memory limits or workload sizing, and how do I size the limit correctly?")
	case "pod.failed":
		b.WriteString("The Pod is in a Failed/Unknown phase. What does that mean, and what are the common causes?")
	case "pod.restarts_high":
		b.WriteString("The container has a high restart count. What's the right way to investigate why it's restarting?")
	case "pod.not_ready":
		b.WriteString("The Pod is Running but not Ready. What probes/conditions should I check, and how do I find the cause?")
	default:
		b.WriteString("What does this Pod state mean and what should I check next?")
	}
	return b.String()
}

func eventPrompt(f Finding) string {
	var b strings.Builder
	b.WriteString("I see Kubernetes Warning event(s) and want to understand them.\n\n")
	fmt.Fprintf(&b, "Namespace: %s\n", f.Namespace)
	writeFields(&b, f, []string{"reason", "involvedObject.kind", "involvedObject.name", "count", "message"})
	b.WriteString("What does this event reason typically indicate, and what are the usual causes?")
	return b.String()
}

func nodePrompt(f Finding) string {
	var b strings.Builder
	b.WriteString("A Kubernetes Node is reporting unhealthy conditions.\n\n")
	fmt.Fprintf(&b, "Node: %s\n", f.Name)
	writeFields(&b, f, []string{
		"condition.Ready", "condition.MemoryPressure",
		"condition.DiskPressure", "condition.PIDPressure",
	})
	b.WriteString("What are the typical causes for these node conditions, and what should I check (kubelet, node OS, kernel logs)?")
	return b.String()
}

func deploymentPrompt(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "A Kubernetes %s has fewer available replicas than desired.\n\n", f.Kind)
	fmt.Fprintf(&b, "%s: %s (namespace: %s)\n", f.Kind, f.Name, f.Namespace)
	writeFields(&b, f, []string{"spec.replicas", "status.availableReplicas"})
	b.WriteString("What are the common causes (pending pods, image pulls, scheduling, PVCs), and what kubectl commands help debug this?")
	return b.String()
}

func pvcPrompt(f Finding) string {
	var b strings.Builder
	b.WriteString("A PersistentVolumeClaim is not Bound.\n\n")
	fmt.Fprintf(&b, "PVC: %s (namespace: %s)\n", f.Name, f.Namespace)
	writeFields(&b, f, []string{"status.phase"})
	b.WriteString("What's the typical reason for this PVC phase, and what should I check (storage class, provisioner, events)?")
	return b.String()
}

func rbacPrompt(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "A %s in my cluster grants wildcard access.\n\n", f.Kind)
	fmt.Fprintf(&b, "%s: %s\n", f.Kind, displayNameOf(f))
	b.WriteString("Is granting verbs=[\"*\"] AND resources=[\"*\"] ever justified, and how do I tell whether this binding is intentional or an over-permissive default?")
	return b.String()
}

func genericPrompt(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Help me understand a Kubernetes object issue.\n\n")
	fmt.Fprintf(&b, "Kind: %s\nName: %s\nNamespace: %s\n", f.Kind, f.Name, f.Namespace)
	writeFields(&b, f, sortedFieldKeys(f.Fields))
	fmt.Fprintf(&b, "Detected rule: %s\n\n", f.Rule)
	b.WriteString("What does this typically mean and what should I check next?")
	return b.String()
}

func displayNameOf(f Finding) string {
	if f.Namespace == "" {
		return f.Name
	}
	return f.Namespace + "/" + f.Name
}

// writeFields prints `key: value` lines for the keys present in f.Fields,
// in the requested order. Unknown keys are silently skipped.
func writeFields(b *strings.Builder, f Finding, keys []string) {
	for _, k := range keys {
		if v := f.Fields[k]; v != "" {
			fmt.Fprintf(b, "%s: %s\n", k, v)
		}
	}
	b.WriteByte('\n')
}

func sortedFieldKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------- Google search ----------

func buildGoogleURL(f Finding) string {
	terms := []string{}
	add := func(s string) {
		if s != "" {
			terms = append(terms, s)
		}
	}

	switch family(f.Rule) {
	case "percona":
		add(f.Kind)
		add(f.Fields["status.state"])
		switch f.Rule {
		case "percona.condition_false":
			add(f.Fields["condition.type"])
			add(f.Fields["condition.reason"])
		case "pxc.component_unhealthy":
			add(f.Fields["component"])
			add(f.Fields["component.status"])
		case "psmdb.replset_unhealthy", "psmdb.mongos_unhealthy":
			add(f.Fields["replset.status"])
			add(f.Fields["mongos.status"])
			add("replset OR mongos")
		case "psmdb.member_down":
			add("replset member state")
			add(f.Fields["member.state"])
		case "pg.instance_unhealthy":
			add("instance set ready size")
		}
		// Surface the operator message as a keyword phrase if present.
		add(messageKeywords(f.Fields["status.message"]))
		add(messageKeywords(f.Fields["condition.message"]))
	case "pod":
		add("Kubernetes Pod")
		add(f.Fields["waiting.reason"])
		add(f.Fields["lastState.terminated.reason"])
		add(f.Fields["status.phase"])
		add("troubleshoot")
	case "event":
		add("Kubernetes")
		add(f.Fields["involvedObject.kind"])
		add(f.Fields["reason"])
		add(messageKeywords(f.Fields["message"]))
	case "node":
		add("Kubernetes Node")
		for _, k := range []string{"condition.Ready", "condition.MemoryPressure", "condition.DiskPressure", "condition.PIDPressure"} {
			if v := f.Fields[k]; v != "" && v != "True" {
				add(strings.TrimPrefix(k, "condition."))
			}
		}
	case "deployment":
		add("Kubernetes")
		add(f.Kind)
		add("availableReplicas less than spec.replicas")
	case "pvc":
		add("Kubernetes PVC")
		add(f.Fields["status.phase"])
		add("not Bound")
	case "rbac":
		add(f.Kind)
		add("wildcard verbs resources")
	default:
		add(f.Kind)
		add(f.Rule)
	}

	query := strings.Join(uniq(terms), " ")
	return "https://www.google.com/search?q=" + url.QueryEscape(query)
}

// messageKeywords trims a status message to a short keyword phrase suitable for a search query.
// Strips pod names and container UIDs that are noise-y for search.
func messageKeywords(msg string) string {
	if msg == "" {
		return ""
	}
	// Drop everything after the first ';' or '(' for brevity.
	for _, sep := range []string{";", "("} {
		if i := strings.Index(msg, sep); i > 0 {
			msg = msg[:i]
		}
	}
	msg = strings.TrimSpace(msg)
	// Cap length.
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
