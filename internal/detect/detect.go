// Package detect classifies file contents into yaml/json/text/binary/unknown
// without modifying the original bytes.
package detect

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Kind names match the file_kind enum stored in the database.
const (
	KindYAML    = "yaml"
	KindJSON    = "json"
	KindText    = "text"
	KindBinary  = "binary"
	KindUnknown = "unknown"
)

// Result describes a classified file.
type Result struct {
	Kind        string
	ContentType string
}

// textExts collects extensions we treat as text candidates regardless of sniffing.
var textExts = map[string]bool{
	".txt": true, ".log": true, ".out": true, ".conf": true,
	".ini": true, ".env": true, ".csv": true, ".tsv": true,
	".md": true, ".cfg": true, ".properties": true, ".sh": true,
	".sql": true, ".xml": true, ".html": true, ".htm": true,
}

// Detect inspects a path + raw bytes and returns the kind plus a content type hint.
// Detection does NOT modify the bytes and is safe to run on the canonical BLOB.
func Detect(path string, raw []byte) Result {
	ext := strings.ToLower(filepath.Ext(path))

	if len(raw) == 0 {
		switch ext {
		case ".yaml", ".yml":
			return Result{Kind: KindYAML, ContentType: "application/yaml"}
		case ".json":
			return Result{Kind: KindJSON, ContentType: "application/json"}
		}
		if textExts[ext] {
			return Result{Kind: KindText, ContentType: "text/plain"}
		}
		return Result{Kind: KindUnknown}
	}

	isUTF8 := utf8.Valid(raw)

	// Extension-driven classification when content is valid UTF-8 and the extension is structured.
	if isUTF8 {
		switch ext {
		case ".yaml", ".yml":
			return Result{Kind: KindYAML, ContentType: "application/yaml"}
		case ".json":
			return Result{Kind: KindJSON, ContentType: "application/json"}
		}
	}

	if !isUTF8 {
		return Result{Kind: KindBinary, ContentType: sniff(raw)}
	}

	// JSON sniff for extensionless or generic files.
	if ext == "" || ext == ".log" {
		trim := bytes.TrimLeft(raw, " \t\r\n")
		if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') && json.Valid(raw) {
			return Result{Kind: KindJSON, ContentType: "application/json"}
		}
	}

	if textExts[ext] || isUTF8 {
		return Result{Kind: KindText, ContentType: sniffText(raw)}
	}

	return Result{Kind: KindUnknown}
}

func sniff(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	n := len(raw)
	if n > 512 {
		n = 512
	}
	return http.DetectContentType(raw[:n])
}

func sniffText(raw []byte) string {
	if ct := sniff(raw); ct != "" {
		return ct
	}
	return "text/plain"
}

// IsText reports whether a kind can be safely rendered as text.
func IsText(kind string) bool {
	switch kind {
	case KindYAML, KindJSON, KindText:
		return true
	}
	return false
}
