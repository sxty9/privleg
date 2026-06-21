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

func TestCatalogRightsAndKeyService(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hostek.json", `{"service":"hostek","version":1,"categories":[
		{"id":"system","label":"System","permissions":[
			{"id":"power","label":"Power","group":"hp_hostek_power"}]}]}`)
	write("remshel.json", `{"service":"remshel","version":1,"categories":[
		{"id":"shell","label":"Shell","permissions":[
			{"id":"access","label":"Access","type":"shell","shell":"/bin/bash"}]}]}`)

	c := New(dir)

	if got := len(c.Rights()); got != 2 {
		t.Fatalf("Rights() size = %d, want 2", got)
	}
	if svc, kind, ok := c.KeyService("hp_hostek_power"); !ok || svc != "hostek" || kind != "group" {
		t.Errorf("KeyService(hp_hostek_power) = %q,%q,%v; want hostek,group,true", svc, kind, ok)
	}
	if svc, kind, ok := c.KeyService("remshel:shell:access"); !ok || svc != "remshel" || kind != "shell" {
		t.Errorf("KeyService(remshel:shell:access) = %q,%q,%v; want remshel,shell,true", svc, kind, ok)
	}
	if _, _, ok := c.KeyService("hp_made_up"); ok {
		t.Error("KeyService of an undeclared key must report ok=false")
	}
}

func TestCatalogMissingDir(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(c.Manifests()) != 0 || c.IsDeclared("hp_x") {
		t.Error("missing dir should yield an empty catalog, not an error")
	}
}
