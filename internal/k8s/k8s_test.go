package k8s

import "testing"

func TestExtractSingleDocument(t *testing.T) {
	doc := `apiVersion: v1
kind: Pod
metadata:
  name: mypod
  namespace: kube-system
`
	docs := ExtractMetadata([]byte(doc))
	if len(docs) != 1 {
		t.Fatalf("want 1 doc, got %d", len(docs))
	}
	d := docs[0]
	if !d.ParsedOK || d.Kind != "Pod" || d.Namespace != "kube-system" || d.Name != "mypod" {
		t.Errorf("unexpected metadata: %+v", d)
	}
}

func TestExtractMultiDocument(t *testing.T) {
	raw := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: a
---
apiVersion: v1
kind: Secret
metadata:
  name: b
  namespace: prod
`)
	docs := ExtractMetadata(raw)
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
	if docs[0].Kind != "ConfigMap" || docs[1].Name != "b" || docs[1].Namespace != "prod" {
		t.Errorf("unexpected metadata: %+v", docs)
	}
}

func TestExtractMalformed(t *testing.T) {
	docs := ExtractMetadata([]byte("key: value\nbad: : : :"))
	if len(docs) == 0 {
		t.Fatal("expected at least one document (possibly with parse error)")
	}
	// We don't require a specific outcome here — only that we didn't crash and
	// that a parse failure is reported via ParsedOK=false when it occurs.
	for _, d := range docs {
		if !d.ParsedOK && d.ParseError == "" {
			t.Error("ParsedOK=false should carry ParseError")
		}
	}
}

func TestExtractEmpty(t *testing.T) {
	if docs := ExtractMetadata([]byte("")); docs != nil {
		t.Errorf("empty input should yield nil, got %d docs", len(docs))
	}
	if docs := ExtractMetadata([]byte("   \n  ")); docs != nil {
		t.Errorf("whitespace-only input should yield nil, got %d docs", len(docs))
	}
}

func TestExtractNonKubernetesYAML(t *testing.T) {
	docs := ExtractMetadata([]byte("foo: 1\nbar: 2\n"))
	if len(docs) != 1 || !docs[0].ParsedOK {
		t.Fatalf("expected one parsed doc, got %+v", docs)
	}
	d := docs[0]
	if d.Kind != "" || d.Name != "" || d.Namespace != "" || d.APIVersion != "" {
		t.Errorf("non-k8s YAML should yield empty fields, got %+v", d)
	}
}
