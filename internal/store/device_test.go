package store

import (
	"path/filepath"
	"testing"
)

func TestBindOrTouchDeviceAutoAndRequire(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.BindOrTouchDevice("auto", "ten1", "u1", "a@b.c", "dev-1", "host", "darwin", "arm64")
	if err != nil || d == nil {
		t.Fatalf("auto bind: %v %v", d, err)
	}
	d2, err := s.BindOrTouchDevice("auto", "ten1", "u1", "a@b.c", "dev-1", "host2", "darwin", "arm64")
	if err != nil || d2.ID != d.ID {
		t.Fatalf("touch: %v %v", d2, err)
	}
	if _, err := s.BindOrTouchDevice("auto", "ten1", "u2", "x@y.z", "dev-1", "", "", ""); err == nil {
		t.Fatal("expected conflict for other user")
	}
	if _, err := s.BindOrTouchDevice("require", "ten1", "u1", "a@b.c", "dev-new", "", "", ""); err == nil {
		t.Fatal("require should fail for unknown device")
	}
	if err := s.RevokeBoundDevice(d.ID); err != nil {
		t.Fatal(err)
	}
}
