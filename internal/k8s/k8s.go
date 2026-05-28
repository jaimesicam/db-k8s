// Package k8s extracts Kubernetes object metadata from YAML files.
// It parses each document in a multi-document stream and returns one Doc per document.
package k8s

import (
	"bytes"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// Doc holds extracted metadata for one YAML document.
type Doc struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	ParsedOK   bool
	ParseError string
}

// ExtractMetadata parses every document in raw and returns one Doc per document
// in the order they appear. A failed document yields a Doc with ParsedOK=false and
// ParseError set, but does not stop processing later documents.
//
// Calling with empty input returns nil (no documents).
func ExtractMetadata(raw []byte) []Doc {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var out []Doc
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			out = append(out, Doc{ParsedOK: false, ParseError: err.Error()})
			// yaml.v3 cannot reliably recover after a decode error, so stop.
			break
		}
		out = append(out, readDoc(&node))
	}
	return out
}

func readDoc(n *yaml.Node) Doc {
	d := Doc{ParsedOK: true}
	root := n
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return d
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		val := root.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "apiVersion":
			if val.Kind == yaml.ScalarNode {
				d.APIVersion = val.Value
			}
		case "kind":
			if val.Kind == yaml.ScalarNode {
				d.Kind = val.Value
			}
		case "metadata":
			d.Namespace, d.Name = readMetadata(val)
		}
	}
	return d
}

func readMetadata(n *yaml.Node) (namespace, name string) {
	if n == nil || n.Kind != yaml.MappingNode {
		return "", ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		val := n.Content[i+1]
		if key.Kind != yaml.ScalarNode || val.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "namespace":
			namespace = val.Value
		case "name":
			name = val.Value
		}
	}
	return
}
