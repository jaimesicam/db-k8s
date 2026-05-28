package archive

import "testing"

func TestSafeRelPath(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"foo/bar.txt", "foo/bar.txt", true},
		{"./foo/bar.txt", "foo/bar.txt", true},
		{"foo//bar.txt", "foo/bar.txt", true},
		{"foo/./bar.txt", "foo/bar.txt", true},
		{"foo\\bar.txt", "foo/bar.txt", true},

		{"/etc/passwd", "", false},
		{"..", "", false},
		{"../etc/passwd", "", false},
		{"foo/../../bar", "", false},
		{"C:\\Windows\\System32", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := SafeRelPath(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("SafeRelPath(%q) = (%q,%v); want (%q,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestIsTarGz(t *testing.T) {
	if !IsTarGz("foo.tar.gz") {
		t.Errorf("foo.tar.gz should be tar.gz")
	}
	if !IsTarGz("FOO.TGZ") {
		t.Errorf("FOO.TGZ should be tar.gz")
	}
	if IsTarGz("foo.zip") {
		t.Errorf("foo.zip is not tar.gz")
	}
}
