// Package archive provides tar.gz iteration helpers used by the importer.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Entry is one regular-file entry read from a tar.gz archive.
type Entry struct {
	RelativePath string // sanitized, slash-separated
	Mode         os.FileMode
	ModTime      string // RFC3339 (empty if zero)
	Content      []byte // raw bytes, exactly as stored
}

// IsTarGz reports whether a path looks like a tar.gz archive.
func IsTarGz(p string) bool {
	low := strings.ToLower(p)
	return strings.HasSuffix(low, ".tar.gz") || strings.HasSuffix(low, ".tgz")
}

// HashFile returns the SHA256 of the file at path, encoded as hex.
func HashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Walk opens a .tar.gz file and calls fn for every regular-file entry.
// Symlinks, hardlinks, directories, and special files are skipped. The relative
// path is sanitized via SafeRelPath before being passed to fn.
//
// rootName returns the leading directory name of the first entry (e.g. "cluster-dump"),
// or "" if the archive is empty.
func Walk(archivePath string, fn func(Entry) error) (rootName string, err error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rootName, fmt.Errorf("tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		rel, ok := SafeRelPath(hdr.Name)
		if !ok {
			// Caller should treat this as an import error; bubble up via fn with an empty Entry.
			if err := fn(Entry{RelativePath: hdr.Name}); err != nil {
				return rootName, err
			}
			continue
		}
		if rootName == "" {
			rootName = firstSegment(rel)
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return rootName, fmt.Errorf("read %q: %w", hdr.Name, err)
		}
		modTime := ""
		if !hdr.ModTime.IsZero() {
			modTime = hdr.ModTime.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		entry := Entry{
			RelativePath: rel,
			Mode:         os.FileMode(hdr.Mode) & os.ModePerm,
			ModTime:      modTime,
			Content:      buf,
		}
		if err := fn(entry); err != nil {
			return rootName, err
		}
	}
	return rootName, nil
}

// SafeRelPath cleans an arbitrary archive path into a safe relative slash path.
// Returns false if the path tries to escape (absolute, drive letter, or contains ..).
func SafeRelPath(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	// Normalize separators.
	clean := strings.ReplaceAll(name, "\\", "/")
	// Strip Windows drive letter like "C:".
	if len(clean) >= 2 && clean[1] == ':' {
		return "", false
	}
	if strings.HasPrefix(clean, "/") {
		return "", false
	}
	clean = path.Clean(clean)
	if clean == "." || clean == "" {
		return "", false
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	// Any ".." segment after Clean means escape.
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", false
		}
	}
	return clean, true
}

func firstSegment(p string) string {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}
