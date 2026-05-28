package detect

import "testing"

func TestDetectYAMLExtension(t *testing.T) {
	r := Detect("foo.yaml", []byte("apiVersion: v1\nkind: Pod\n"))
	if r.Kind != KindYAML {
		t.Errorf("want yaml, got %q", r.Kind)
	}
}

func TestDetectJSONValid(t *testing.T) {
	r := Detect("foo.json", []byte(`{"a":1}`))
	if r.Kind != KindJSON {
		t.Errorf("want json, got %q", r.Kind)
	}
}

func TestDetectJSONByContent(t *testing.T) {
	r := Detect("payload", []byte(`{"a":1}`))
	if r.Kind != KindJSON {
		t.Errorf("want json, got %q", r.Kind)
	}
}

func TestDetectTextByExtension(t *testing.T) {
	r := Detect("server.log", []byte("hello world\n"))
	if r.Kind != KindText {
		t.Errorf("want text, got %q", r.Kind)
	}
}

func TestDetectBinaryByInvalidUTF8(t *testing.T) {
	r := Detect("blob.bin", []byte{0xff, 0xfe, 0x00, 0x01, 0x02})
	if r.Kind != KindBinary {
		t.Errorf("want binary, got %q", r.Kind)
	}
}

func TestDetectEmpty(t *testing.T) {
	if Detect("foo.yaml", nil).Kind != KindYAML {
		t.Error("empty .yaml should still be yaml")
	}
	if Detect("foo.txt", nil).Kind != KindText {
		t.Error("empty .txt should still be text")
	}
	if Detect("mystery", nil).Kind != KindUnknown {
		t.Error("empty unknown ext should be unknown")
	}
}

func TestIsText(t *testing.T) {
	if !IsText(KindYAML) || !IsText(KindJSON) || !IsText(KindText) {
		t.Error("yaml/json/text should be text-renderable")
	}
	if IsText(KindBinary) || IsText(KindUnknown) {
		t.Error("binary/unknown should not be text-renderable")
	}
}
