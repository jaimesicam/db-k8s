# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`db-k8s` is a CLI tool that imports Kubernetes debug dumps (produced by `pt-k8s-debug-collector`) into SQLite, then generates a static HTML report. Every collected file must be browsable, readable, and downloadable as a raw file — without any internet access or running cluster.

## Development Commands

```bash
# Build
go build ./cmd/db-k8s

# Run tests
go test ./...

# Run a single test package
go test ./internal/importer/...

# Run a specific test
go test ./internal/importer/ -run TestImportTarGz

# Run with race detector
go test -race ./...

# Import a sample archive
go run ./cmd/db-k8s import ./samples/1/cluster-dump.tar.gz

# Generate a report
go run ./cmd/db-k8s report --output ./db-k8s-report

# Other CLI commands
go run ./cmd/db-k8s list-dumps
go run ./cmd/db-k8s list-files
go run ./cmd/db-k8s show-file 1
go run ./cmd/db-k8s --db ./custom.db import ./samples/2/cluster-dump.tar.gz
```

## Package Layout

```
cmd/db-k8s/        CLI entrypoint — command parsing only, delegates to internal packages
internal/archive/  tar.gz iteration and extraction helpers
internal/db/       SQLite schema, migrations, all inserts and queries
internal/detect/   File kind detection (yaml/json/text/binary/unknown)
internal/importer/ Import orchestration for archives and directories
internal/k8s/      YAML metadata extraction (apiVersion, kind, namespace, name)
internal/report/   Static HTML generation, raw file export, hash verification
```

## Sample Data

Samples live in `samples/<n>/cluster-dump.tar.gz` (not `@samples/` as mentioned in some docs). There are 12 samples (1–12). Tests must walk `samples/` and test against all of them — do not hardcode `samples/1`.

Archive structure inside a sample:
```
cluster-dump/
  nodes.yaml
  errors.txt
  <namespace>/
    pods.yaml
    deployments.yaml
    <resource-type>.yaml ...
    <pod-name>/
      logs.txt
      summary.txt
    secret/
      <name>.yaml
```

## Key Constraints

- **Lossless storage**: raw bytes go into SQLite as a BLOB, SHA256 is computed from those raw bytes. Do not normalize, trim, or reserialize content.
- **Raw BLOB is canonical**: `text_content` is a derived convenience field only.
- **Never abort an import for one bad file**: record errors in `import_errors`, continue.
- **Path safety**: sanitize all paths from archives — reject `..`, absolute paths, Windows drive letters. `relative_path` in SQLite must always be a safe relative path.
- **Offline**: no external CDN assets in the HTML report, no network calls.
- **Import regular files only**: skip symlinks, hard links; record directories as metadata only.

## SQLite Schema (authoritative)

```sql
CREATE TABLE IF NOT EXISTS dumps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL,
    source_type TEXT NOT NULL,   -- 'tar.gz' or 'directory'
    source_sha256 TEXT,
    imported_at TEXT NOT NULL,
    root_name TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_id INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    extension TEXT,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    content_type TEXT,
    file_kind TEXT NOT NULL,     -- yaml/json/text/binary/unknown
    raw_content BLOB NOT NULL,
    text_content TEXT,
    line_count INTEGER,
    file_mode TEXT,
    modified_time TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (dump_id) REFERENCES dumps(id)
);

CREATE TABLE IF NOT EXISTS yaml_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    api_version TEXT,
    kind TEXT,
    namespace TEXT,
    name TEXT,
    parsed_ok INTEGER NOT NULL,
    parse_error TEXT,
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE TABLE IF NOT EXISTS import_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_id INTEGER,
    relative_path TEXT,
    error_type TEXT NOT NULL,
    error_message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (dump_id) REFERENCES dumps(id)
);
```

Sort file listings by `dump_id, relative_path` for deterministic output.

## File Kind Detection

Priority: extension hint → UTF-8 validity → content parsing
- `.yaml`/`.yml` → yaml candidate; `.json` → json candidate
- `.txt`, `.log`, `.out`, `.conf`, `.ini`, `.env`, `.csv`, `.tsv` → text candidate
- Invalid UTF-8 → binary
- Empty files → import as `unknown` or `text`, never skip
- Unknown but valid UTF-8 → `text`
- Multi-document YAML (`---` separator) → one `yaml_documents` row per document

## HTML Report Layout

```
db-k8s-report/
  index.html        Summary: counts, sizes, dump list
  files.html        Searchable table of all files (client-side JS filter)
  objects.html      Kubernetes object index (kind/namespace/name)
  assets/style.css
  assets/script.js
  dumps/dump-<id>.html
  files/file-<id>.html
  raw/dump-<id>/<original relative path>   ← exact bytes from SQLite
```

Raw files are written from the BLOB and verified against stored SHA256. Every file detail page must link to its raw file. Report must work fully offline — no external resources.

## Preferred Libraries

- SQLite: `modernc.org/sqlite` (pure Go, no CGo)
- YAML: `gopkg.in/yaml.v3`
- Archive/hash/template: Go standard library only

## Default Paths

- Database: `db-k8s.db` (in working directory)
- Report output: `./db-k8s-report`
- Override with `--db` flag globally
