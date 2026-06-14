package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hostek.json", `{"service":"hostek","version":1,"categories":[
		{"id":"system","label":"System","permissions":[
			{"id":"power","label":"Power","group":"hp_hostek_power","dangerous":true}]}]}`)
	write("samba.json", `{"service":"samba","version":1,"categories":[
		{"id":"shares","label":"Shares","permissions":[
			{"id":"fw","label":"Family write","group":"hp_samba_family_write","default":true}]}]}`)
	write("broken.json", `{ not json `)         // malformed → skipped, must not break load
	write("notes.txt", `ignored non-json file`) // non-json → ignored

	c := New(dir)

	if got := len(c.Manifests()); got != 2 {
		t.Fatalf("want 2 manifests, got %d", got)
	}
	if svc, ok := c.ServiceOf("hp_hostek_power"); !ok || svc != "hostek" {
		t.Errorf("ServiceOf(hp_hostek_power) = %q,%v; want hostek,true", svc, ok)
	}
	if svc, ok := c.ServiceOf("hp_samba_family_write"); !ok || svc != "samba" {
		t.Errorf("ServiceOf(hp_samba_family_write) = %q,%v; want samba,true", svc, ok)
	}
	if c.IsDeclared("sudo") {
		t.Error("sudo must never be a declared right")
	}
	if c.IsDeclared("hp_made_up") {
		t.Error("undeclared group must not be declared")
	}
	if got := c.DeclaredSet(); len(got) != 2 {
		t.Errorf("DeclaredSet size = %d, want 2", len(got))
	}
}

func TestCatalogMissingDir(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(c.Manifests()) != 0 || c.IsDeclared("hp_x") {
		t.Error("missing dir should yield an empty catalog, not an error")
	}
}
