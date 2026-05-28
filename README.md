# db-k8s

`db-k8s` is a local, offline CLI for reading and exploring Kubernetes debug dumps produced by [`pt-k8s-debug-collector`](https://github.com/percona/percona-toolkit). It imports a `cluster.tar.gz` archive (or an already-extracted directory) into a SQLite database, then generates a self-contained static HTML report where every collected file is browsable, readable, and downloadable as a raw file.

No running cluster, no internet, no external services.

---

## Build

```bash
go build ./cmd/db-k8s
```

This produces a `db-k8s` binary in the current directory. Pure Go — no CGo required (uses `modernc.org/sqlite`).

## Quick start

```bash
# Import a dump
./db-k8s import ./cluster.tar.gz

# Or an extracted directory
./db-k8s import ./cluster

# Generate the report
./db-k8s report --output ./db-k8s-report

# Browse
xdg-open ./db-k8s-report/index.html
```

## Commands

```text
db-k8s [--db PATH] <command> [arguments]

Commands:
  import <path>                   Import a .tar.gz archive or extracted directory
  report [--output DIR]           Generate the static HTML report (default ./db-k8s-report)
  list-dumps                      List imported dumps
  list-files                      List imported files
  show-file <file-id>             Show file metadata (and text content if safe)
  concerns [--severity SEV]       List analyzer findings (critical|warning|info)
           [--dump N]
  help                            Show usage
```

Global flag `--db PATH` overrides the default database path (`./db-k8s.db`).

### Examples

```bash
db-k8s --db ./mycluster.db import ./samples/1/cluster-dump.tar.gz
db-k8s --db ./mycluster.db list-dumps
db-k8s --db ./mycluster.db list-files
db-k8s --db ./mycluster.db show-file 42
db-k8s --db ./mycluster.db report --output ./report
```

Multiple imports can share the same database — each gets its own dump ID.

---

## Concerns: per-YAML summaries and findings

The report and CLI surface a per-YAML one-line summary plus a structured list of **findings** — concerns extracted by a rule-based diagnostic layer. Analysis runs at report generation time on the data already in SQLite; it never modifies the canonical BLOB.

The rule set covers three families:

* **Core Kubernetes** — `pod.failed`, `pod.crashloop`, `pod.oomkilled`, `pod.restarts_high`, `pod.not_ready`, `event.warning` (aggregated per `(kind, reason)`), `deployment.replicas_mismatch`, `pvc.pending`, `node.not_ready`, `rbac.wildcard`.
* **Percona operators (PXC / PSMDB / PG)** — shared rules that walk `status.state`, `status.conditions[]`, `status.ready` / `status.size`, and `status.message`:
  * `percona.state_error`, `percona.state_initializing`, `percona.state_other`
  * `percona.replica_mismatch`, `percona.message_present`
  * `percona.condition_false` (with severity escalated to critical when the condition name/reason mentions backup/repo/pgBackRest, and reduced to info for `Paused`)
* **Operator-specific sub-component checks** — `pxc.component_unhealthy` (pxc/haproxy/proxysql), `psmdb.replset_unhealthy` / `psmdb.member_down` (MongoDB replset states 1=PRIMARY, 2=SECONDARY, 7=ARBITER) / `psmdb.mongos_unhealthy`, `pg.instance_unhealthy`.

The report adds a **Concerns** page (`concerns.html`) with a client-side filter by severity, plus per-dump and per-file findings sections. Every file detail page shows a `Summary:` line and any per-file findings above the rendered content.

### Investigate panel

Each finding includes an **Investigate** disclosure with two next steps:

* a **Google search** link with a pre-encoded query, and
* a **copyable AI prompt** filled with the finding's curated context (kind, name, namespace, status fields, conditions, operator message) plus a question tuned to the rule.

The Investigate content is built from `Finding` fields only — never from the raw YAML BLOB. `Secret.data`, `ConfigMap.data`, environment variables, and image-pull secrets are never included. The raw-file link is always available for users who choose to share more.

### CLI

```bash
db-k8s concerns                                  # all findings
db-k8s concerns --severity critical              # only critical
db-k8s concerns --severity warning --dump 2      # warning+critical for dump 2
db-k8s show-file 17                              # appends summary + per-file findings
```

## How integrity is preserved

* The raw bytes of every imported file are stored in SQLite as a BLOB. **The BLOB is the source of truth.**
* `text_content` is only stored when the file is text-decodable as UTF-8; it is a convenience field — it is never used in place of the BLOB.
* SHA256 is computed over the original raw bytes at import time and re-verified on raw export.
* Nothing is trimmed, normalized, or reserialized.
* The HTML report's raw-file links point to bytes that were re-extracted from the BLOB and bit-for-bit identical to the original file.

After import, the original `cluster.tar.gz` and extracted directory can be discarded — everything needed to regenerate the report is in the database.

## How raw file links work

The report writes every file under `db-k8s-report/raw/dump-<id>/<original relative path>`. Every file detail page links to that path. If two files in a dump have the same path (or one entry is a file while another shares its prefix as a directory — yes, this happens in real dumps), conflicts are resolved deterministically by appending `-id<file-id>` to the basename, and the file detail page links to the resolved path.

## File kind detection

Each file is classified as one of `yaml`, `json`, `text`, `binary`, or `unknown`:

* Extension hints (`.yaml`, `.yml`, `.json`) win when content is valid UTF-8.
* Invalid UTF-8 → `binary`.
* Common text extensions (`.txt`, `.log`, `.out`, `.conf`, `.ini`, `.env`, `.csv`, `.tsv`, ...) → `text`.
* JSON-looking content without an extension is sniffed and accepted.
* Everything else valid UTF-8 falls back to `text`; otherwise `unknown`.

For YAML files (including multi-document streams separated by `---`), `apiVersion`, `kind`, `metadata.namespace`, and `metadata.name` are extracted per document and shown in the report's Kubernetes object index. Parse failures are recorded but never abort the import.

---

## Testing

Sample dumps live in `samples/` (12 archives, `samples/1/cluster-dump.tar.gz` through `samples/12/cluster-dump.tar.gz`). The test suite walks `samples/` and imports each sample into a temporary database. To run:

```bash
go test ./...
```

The tests verify:

* `.tar.gz` and directory imports both succeed
* Multiple dumps coexist in one database
* Stored SHA256 matches the raw bytes
* Raw bytes match the original tar entries
* Text content is preserved exactly (CRLF, trailing whitespace, missing newlines)
* Path traversal entries (`..`, absolute, Windows drive letters) are rejected
* Malformed YAML does not break the import
* Every file detail page in the generated report has a working raw-file link
* Every exported raw file matches the stored hash
* A traversal entry inserted directly into the DB cannot escape the report output directory

---

## Database schema

See `internal/db/db.go`. The four tables are:

* `dumps` — one row per imported source
* `files` — one row per regular file (BLOB included)
* `yaml_documents` — one row per YAML document (multi-doc files produce multiple rows)
* `import_errors` — per-file errors (never fatal)

---

## License

See `LICENSE`.
