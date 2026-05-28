// Package importer orchestrates ingesting a tar.gz archive or extracted directory
// into the SQLite database.
package importer

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/db-k8s/db-k8s/internal/archive"
	"github.com/db-k8s/db-k8s/internal/db"
	"github.com/db-k8s/db-k8s/internal/detect"
	"github.com/db-k8s/db-k8s/internal/k8s"
)

// Source describes what was imported.
type Source string

const (
	SourceTarGz     Source = "tar.gz"
	SourceDirectory Source = "directory"
)

// Result is returned by Import.
type Result struct {
	DumpID     int64
	FilesAdded int64
	BytesAdded int64
	Errors     int64
}

// Import detects whether path is an archive or directory and ingests it.
func Import(d *db.DB, path string) (Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.IsDir() {
		return ImportDirectory(d, path)
	}
	if archive.IsTarGz(path) {
		return ImportArchive(d, path)
	}
	return Result{}, fmt.Errorf("unsupported source %q: expected .tar.gz or directory", path)
}

// ImportArchive imports a .tar.gz file.
func ImportArchive(d *db.DB, archivePath string) (Result, error) {
	absPath, err := filepath.Abs(archivePath)
	if err != nil {
		absPath = archivePath
	}
	hash, err := archive.HashFile(archivePath)
	if err != nil {
		return Result{}, fmt.Errorf("hash %q: %w", archivePath, err)
	}
	dumpID, err := d.InsertDump(db.Dump{
		SourcePath:   absPath,
		SourceType:   string(SourceTarGz),
		SourceSHA256: hash,
	})
	if err != nil {
		return Result{}, err
	}

	res := Result{DumpID: dumpID}
	rootName, err := archive.Walk(archivePath, func(e archive.Entry) error {
		if e.Content == nil && e.RelativePath != "" {
			// unsafe path
			_ = d.InsertImportError(dumpID, e.RelativePath, "unsafe_path",
				"path rejected by safety check")
			res.Errors++
			return nil
		}
		err := storeFile(d, dumpID, e.RelativePath, e.Content,
			e.Mode.String(), e.ModTime)
		if err != nil {
			_ = d.InsertImportError(dumpID, e.RelativePath, "store_file", err.Error())
			res.Errors++
			return nil
		}
		res.FilesAdded++
		res.BytesAdded += int64(len(e.Content))
		return nil
	})
	if err != nil {
		_ = d.InsertImportError(dumpID, "", "archive_walk", err.Error())
		res.Errors++
	}
	if rootName != "" {
		_, _ = d.Exec(`UPDATE dumps SET root_name = ? WHERE id = ?`, rootName, dumpID)
	}
	return res, nil
}

// ImportDirectory imports an already-extracted directory.
func ImportDirectory(d *db.DB, dirPath string) (Result, error) {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		absPath = dirPath
	}
	root := filepath.Base(absPath)
	dumpID, err := d.InsertDump(db.Dump{
		SourcePath: absPath,
		SourceType: string(SourceDirectory),
		RootName:   root,
	})
	if err != nil {
		return Result{}, err
	}

	res := Result{DumpID: dumpID}
	err = filepath.WalkDir(absPath, func(p string, dirent fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			_ = d.InsertImportError(dumpID, p, "walk_dir", walkErr.Error())
			res.Errors++
			return nil
		}
		if dirent.IsDir() {
			return nil
		}
		// Only regular files; skip symlinks and special files.
		info, infoErr := dirent.Info()
		if infoErr != nil {
			_ = d.InsertImportError(dumpID, p, "stat", infoErr.Error())
			res.Errors++
			return nil
		}
		if info.Mode()&os.ModeType != 0 {
			// Skip symlinks, devices, sockets, etc.
			return nil
		}
		rel, relErr := filepath.Rel(absPath, p)
		if relErr != nil {
			_ = d.InsertImportError(dumpID, p, "rel_path", relErr.Error())
			res.Errors++
			return nil
		}
		// Normalize to slash-separated relative path; reconstruct with leading root segment
		// so layout matches what a tar.gz import would store.
		rel = filepath.ToSlash(rel)
		safeRel, ok := archive.SafeRelPath(filepath.ToSlash(filepath.Join(root, rel)))
		if !ok {
			_ = d.InsertImportError(dumpID, rel, "unsafe_path", "rejected")
			res.Errors++
			return nil
		}

		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			_ = d.InsertImportError(dumpID, safeRel, "read", readErr.Error())
			res.Errors++
			return nil
		}
		modTime := ""
		if t := info.ModTime(); !t.IsZero() {
			modTime = t.UTC().Format(time.RFC3339)
		}
		if err := storeFile(d, dumpID, safeRel, raw, info.Mode().String(), modTime); err != nil {
			_ = d.InsertImportError(dumpID, safeRel, "store_file", err.Error())
			res.Errors++
			return nil
		}
		res.FilesAdded++
		res.BytesAdded += int64(len(raw))
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// storeFile is the per-file pipeline: detect, hash, extract text/YAML, insert.
// raw is treated as the canonical source; nothing here mutates it.
func storeFile(d *db.DB, dumpID int64, relPath string, raw []byte, mode, modTime string) error {
	if raw == nil {
		raw = []byte{} // distinguish "empty" from nil for BLOB; schema requires NOT NULL
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	res := detect.Detect(relPath, raw)

	var text sql.NullString
	var lineCount sql.NullInt64
	if detect.IsText(res.Kind) && utf8.Valid(raw) {
		text = sql.NullString{String: string(raw), Valid: true}
		if len(raw) == 0 {
			lineCount = sql.NullInt64{Int64: 0, Valid: true}
		} else {
			lineCount = sql.NullInt64{Int64: int64(bytes.Count(raw, []byte("\n"))) +
				boolToInt64(!bytes.HasSuffix(raw, []byte("\n"))), Valid: true}
		}
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	fileName := filepath.Base(relPath)

	fileID, err := d.InsertFile(db.File{
		DumpID:       dumpID,
		RelativePath: relPath,
		FileName:     fileName,
		Extension:    ext,
		SizeBytes:    int64(len(raw)),
		SHA256:       hash,
		ContentType:  res.ContentType,
		FileKind:     res.Kind,
		TextContent:  text,
		LineCount:    lineCount,
		FileMode:     mode,
		ModifiedTime: modTime,
	}, raw)
	if err != nil {
		return err
	}

	if res.Kind == detect.KindYAML {
		docs := k8s.ExtractMetadata(raw)
		if len(docs) == 0 {
			// Record a placeholder so we know we tried (empty yaml file etc.).
			_ = d.InsertYAMLDoc(db.YAMLDoc{FileID: fileID, ParsedOK: true})
		}
		for _, doc := range docs {
			y := db.YAMLDoc{
				FileID:     fileID,
				APIVersion: doc.APIVersion,
				Kind:       doc.Kind,
				Namespace:  doc.Namespace,
				Name:       doc.Name,
				ParsedOK:   doc.ParsedOK,
				ParseError: doc.ParseError,
			}
			if insErr := d.InsertYAMLDoc(y); insErr != nil {
				return insErr
			}
		}
	}
	return nil
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
