// Package db owns the SQLite schema and all queries for db-k8s.
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS dumps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL,
    source_type TEXT NOT NULL,
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
    file_kind TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_files_dump_id ON files(dump_id);
CREATE INDEX IF NOT EXISTS idx_files_relative_path ON files(relative_path);
CREATE INDEX IF NOT EXISTS idx_files_kind ON files(file_kind);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_yaml_file_id ON yaml_documents(file_id);
CREATE INDEX IF NOT EXISTS idx_yaml_kind ON yaml_documents(kind);
CREATE INDEX IF NOT EXISTS idx_yaml_namespace_name ON yaml_documents(namespace, name);
`

// DB wraps *sql.DB with helpers for the db-k8s schema.
type DB struct {
	*sql.DB
	path string
}

// Open opens (or creates) the SQLite database at path and ensures the schema exists.
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	if _, err := sqlDB.Exec(schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if _, err := sqlDB.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable foreign_keys: %w", err)
	}
	return &DB{DB: sqlDB, path: path}, nil
}

// Path returns the on-disk path the DB was opened from.
func (d *DB) Path() string { return d.path }

// Dump matches a row in `dumps`.
type Dump struct {
	ID           int64
	SourcePath   string
	SourceType   string
	SourceSHA256 string
	ImportedAt   string
	RootName     string
	Notes        string
}

// File matches a row in `files` (without the BLOB by default).
type File struct {
	ID           int64
	DumpID       int64
	RelativePath string
	FileName     string
	Extension    string
	SizeBytes    int64
	SHA256       string
	ContentType  string
	FileKind     string
	TextContent  sql.NullString
	LineCount    sql.NullInt64
	FileMode     string
	ModifiedTime string
	CreatedAt    string
}

// YAMLDoc matches a row in `yaml_documents`.
type YAMLDoc struct {
	ID         int64
	FileID     int64
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	ParsedOK   bool
	ParseError string
}

// InsertDump creates a new dump row and returns the new ID.
func (d *DB) InsertDump(dp Dump) (int64, error) {
	if dp.ImportedAt == "" {
		dp.ImportedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	res, err := d.Exec(
		`INSERT INTO dumps (source_path, source_type, source_sha256, imported_at, root_name, notes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		dp.SourcePath, dp.SourceType, nullable(dp.SourceSHA256), dp.ImportedAt,
		nullable(dp.RootName), nullable(dp.Notes),
	)
	if err != nil {
		return 0, fmt.Errorf("insert dump: %w", err)
	}
	return res.LastInsertId()
}

// InsertFile creates a new file row and returns the new ID. raw must be the canonical bytes.
func (d *DB) InsertFile(f File, raw []byte) (int64, error) {
	if f.CreatedAt == "" {
		f.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	res, err := d.Exec(
		`INSERT INTO files (
			dump_id, relative_path, file_name, extension, size_bytes, sha256,
			content_type, file_kind, raw_content, text_content, line_count,
			file_mode, modified_time, created_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.DumpID, f.RelativePath, f.FileName, nullable(f.Extension),
		f.SizeBytes, f.SHA256, nullable(f.ContentType), f.FileKind,
		raw, nullableNS(f.TextContent), nullableNI(f.LineCount),
		nullable(f.FileMode), nullable(f.ModifiedTime), f.CreatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("insert file %q: %w", f.RelativePath, err)
	}
	return res.LastInsertId()
}

// InsertYAMLDoc records one parsed (or failed) YAML document for a file.
func (d *DB) InsertYAMLDoc(y YAMLDoc) error {
	parsed := 0
	if y.ParsedOK {
		parsed = 1
	}
	_, err := d.Exec(
		`INSERT INTO yaml_documents (file_id, api_version, kind, namespace, name, parsed_ok, parse_error)
		 VALUES (?,?,?,?,?,?,?)`,
		y.FileID, nullable(y.APIVersion), nullable(y.Kind),
		nullable(y.Namespace), nullable(y.Name), parsed, nullable(y.ParseError),
	)
	if err != nil {
		return fmt.Errorf("insert yaml_document: %w", err)
	}
	return nil
}

// InsertImportError records a per-file error without failing the import.
func (d *DB) InsertImportError(dumpID int64, relPath, errType, errMsg string) error {
	_, err := d.Exec(
		`INSERT INTO import_errors (dump_id, relative_path, error_type, error_message, created_at)
		 VALUES (?,?,?,?,?)`,
		nullableI64(dumpID), nullable(relPath), errType, errMsg,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert import_error: %w", err)
	}
	return nil
}

// ListDumps returns all dumps in id order.
func (d *DB) ListDumps() ([]Dump, error) {
	rows, err := d.Query(`SELECT id, source_path, source_type,
		COALESCE(source_sha256,''), imported_at, COALESCE(root_name,''), COALESCE(notes,'')
		FROM dumps ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Dump
	for rows.Next() {
		var d Dump
		if err := rows.Scan(&d.ID, &d.SourcePath, &d.SourceType, &d.SourceSHA256,
			&d.ImportedAt, &d.RootName, &d.Notes); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDump returns a single dump or sql.ErrNoRows.
func (d *DB) GetDump(id int64) (Dump, error) {
	var dp Dump
	err := d.QueryRow(`SELECT id, source_path, source_type, COALESCE(source_sha256,''),
		imported_at, COALESCE(root_name,''), COALESCE(notes,'')
		FROM dumps WHERE id = ?`, id).Scan(
		&dp.ID, &dp.SourcePath, &dp.SourceType, &dp.SourceSHA256,
		&dp.ImportedAt, &dp.RootName, &dp.Notes,
	)
	return dp, err
}

// ListFiles returns file metadata (no BLOB) sorted by (dump_id, relative_path).
func (d *DB) ListFiles() ([]File, error) {
	rows, err := d.Query(`SELECT id, dump_id, relative_path, file_name,
		COALESCE(extension,''), size_bytes, sha256, COALESCE(content_type,''),
		file_kind, text_content, line_count, COALESCE(file_mode,''),
		COALESCE(modified_time,''), created_at
		FROM files ORDER BY dump_id, relative_path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFiles(rows)
}

// ListFilesByDump returns file metadata for one dump in path order.
func (d *DB) ListFilesByDump(dumpID int64) ([]File, error) {
	rows, err := d.Query(`SELECT id, dump_id, relative_path, file_name,
		COALESCE(extension,''), size_bytes, sha256, COALESCE(content_type,''),
		file_kind, text_content, line_count, COALESCE(file_mode,''),
		COALESCE(modified_time,''), created_at
		FROM files WHERE dump_id = ? ORDER BY relative_path`, dumpID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFiles(rows)
}

// GetFile returns one file's metadata (without BLOB) or sql.ErrNoRows.
func (d *DB) GetFile(id int64) (File, error) {
	row := d.QueryRow(`SELECT id, dump_id, relative_path, file_name,
		COALESCE(extension,''), size_bytes, sha256, COALESCE(content_type,''),
		file_kind, text_content, line_count, COALESCE(file_mode,''),
		COALESCE(modified_time,''), created_at
		FROM files WHERE id = ?`, id)
	var f File
	err := row.Scan(&f.ID, &f.DumpID, &f.RelativePath, &f.FileName, &f.Extension,
		&f.SizeBytes, &f.SHA256, &f.ContentType, &f.FileKind, &f.TextContent,
		&f.LineCount, &f.FileMode, &f.ModifiedTime, &f.CreatedAt)
	return f, err
}

// GetRawContent returns just the BLOB for a file.
func (d *DB) GetRawContent(fileID int64) ([]byte, error) {
	var raw []byte
	err := d.QueryRow(`SELECT raw_content FROM files WHERE id = ?`, fileID).Scan(&raw)
	return raw, err
}

// ListYAMLDocsByFile returns YAML rows for a file.
func (d *DB) ListYAMLDocsByFile(fileID int64) ([]YAMLDoc, error) {
	rows, err := d.Query(`SELECT id, file_id, COALESCE(api_version,''),
		COALESCE(kind,''), COALESCE(namespace,''), COALESCE(name,''),
		parsed_ok, COALESCE(parse_error,'')
		FROM yaml_documents WHERE file_id = ? ORDER BY id`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanYAML(rows)
}

// ListAllYAMLDocs returns every parsed YAML row (joined with file context for the index page).
func (d *DB) ListAllYAMLDocs() ([]YAMLDoc, error) {
	rows, err := d.Query(`SELECT id, file_id, COALESCE(api_version,''),
		COALESCE(kind,''), COALESCE(namespace,''), COALESCE(name,''),
		parsed_ok, COALESCE(parse_error,'')
		FROM yaml_documents ORDER BY kind, namespace, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanYAML(rows)
}

// CountFiles returns total file count and total bytes across all dumps.
func (d *DB) CountFiles() (count int64, bytes int64, err error) {
	err = d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM files`).Scan(&count, &bytes)
	return
}

// CountByKind returns a map of file_kind -> count.
func (d *DB) CountByKind() (map[string]int64, error) {
	rows, err := d.Query(`SELECT file_kind, COUNT(*) FROM files GROUP BY file_kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var c int64
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// DumpFileStats returns file count and total bytes for one dump.
func (d *DB) DumpFileStats(dumpID int64) (count int64, bytes int64, err error) {
	err = d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM files WHERE dump_id = ?`,
		dumpID).Scan(&count, &bytes)
	return
}

// DumpKindCounts returns per-kind counts for one dump.
func (d *DB) DumpKindCounts(dumpID int64) (map[string]int64, error) {
	rows, err := d.Query(`SELECT file_kind, COUNT(*) FROM files WHERE dump_id = ? GROUP BY file_kind`,
		dumpID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var c int64
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

func scanFiles(rows *sql.Rows) ([]File, error) {
	var out []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.DumpID, &f.RelativePath, &f.FileName, &f.Extension,
			&f.SizeBytes, &f.SHA256, &f.ContentType, &f.FileKind, &f.TextContent,
			&f.LineCount, &f.FileMode, &f.ModifiedTime, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func scanYAML(rows *sql.Rows) ([]YAMLDoc, error) {
	var out []YAMLDoc
	for rows.Next() {
		var y YAMLDoc
		var parsed int
		if err := rows.Scan(&y.ID, &y.FileID, &y.APIVersion, &y.Kind, &y.Namespace,
			&y.Name, &parsed, &y.ParseError); err != nil {
			return nil, err
		}
		y.ParsedOK = parsed != 0
		out = append(out, y)
	}
	return out, rows.Err()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableI64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableNS(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

func nullableNI(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return n.Int64
}
