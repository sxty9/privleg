package rights

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"privleg/internal/catalog"
	"privleg/internal/users"
)

// testCatalog builds a catalog with one group right (hp_hostek_power) and one shell right
// (remshel:shell:access) and one more group right (hp_samba_family_write).
func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hostek.json", `{"service":"hostek","version":1,"categories":[
		{"id":"system","label":"System","permissions":[
			{"id":"power","label":"Power","group":"hp_hostek_power"}]}]}`)
	write("samba.json", `{"service":"samba","version":1,"categories":[
		{"id":"shares","label":"Shares","permissions":[
			{"id":"fw","label":"FW","group":"hp_samba_family_write"}]}]}`)
	write("remshel.json", `{"service":"remshel","version":1,"categories":[
		{"id":"shell","label":"Shell","permissions":[
			{"id":"access","label":"Access","type":"shell","shell":"/bin/bash"}]}]}`)
	return catalog.New(dir)
}

type fakeLive struct {
	users map[string]users.User
	shell map[string]bool
}

func (f fakeLive) Resolve(name string) users.User { return f.users[name] }
func (f fakeLive) ShellEnabled(name string) bool  { return f.shell[name] }
func (f fakeLive) IsManaged(name string) bool     { _, ok := f.users[name]; return ok }

type grantCall struct {
	group string
	on    bool
}
type shellCall struct{ on bool }

type fakeApplier struct {
	grants    []grantCall
	shells    []shellCall
	failGroup string
}

func (f *fakeApplier) SetGrant(_, g string, on bool) error {
	f.grants = append(f.grants, grantCall{g, on})
	if g == f.failGroup {
		return errors.New("boom")
	}
	return nil
}
func (f *fakeApplier) SetShell(_ string, on bool) error {
	f.shells = append(f.shells, shellCall{on})
	return nil
}

func newTestMat(t *testing.T, live fakeLive, ap *fakeApplier) (*Materializer, *Store) {
	t.Helper()
	st, _ := Open(filepath.Join(t.TempDir(), "rights.json"))
	return newMaterializer(st, testCatalog(t), live, ap), st
}

func TestMaterializeAdminNoOp(t *testing.T) {
	live := fakeLive{users: map[string]users.User{"root": {Username: "root", IsAdmin: true}}}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	_ = st.SetUser("root", UserConfig{Overrides: map[string]string{"hp_hostek_power": "on"}})
	if err := m.Materialize("root"); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 0 || len(ap.shells) != 0 {
		t.Error("admins must never be materialized")
	}
}

func TestMaterializeUnconfiguredNoOp(t *testing.T) {
	live := fakeLive{users: map[string]users.User{"alice": {Username: "alice", Groups: []string{"hp_hostek_power"}}}}
	ap := &fakeApplier{}
	m, _ := newTestMat(t, live, ap)
	if err := m.Materialize("alice"); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 0 || len(ap.shells) != 0 {
		t.Error("a user with no stored config must not be touched")
	}
}

func TestBaselineImportsLiveRights(t *testing.T) {
	live := fakeLive{
		users: map[string]users.User{"alice": {Username: "alice", Groups: []string{"hp_hostek_power", "family"}}},
		shell: map[string]bool{"alice": true},
	}
	m, _ := newTestMat(t, live, &fakeApplier{})
	cfg := m.BaselineConfig("alice")
	// hp_hostek_power held → on; family is undeclared → ignored; shell on → shell key on.
	if cfg.Overrides["hp_hostek_power"] != "on" {
		t.Errorf("held group should import as on: %v", cfg.Overrides)
	}
	if cfg.Overrides["remshel:shell:access"] != "on" {
		t.Errorf("enabled shell should import as on: %v", cfg.Overrides)
	}
	if _, present := cfg.Overrides["family"]; present {
		t.Error("undeclared groups must not be imported")
	}
}

func TestMaterializeGroupAndShellGrant(t *testing.T) {
	live := fakeLive{
		users: map[string]users.User{"alice": {Username: "alice"}}, // holds nothing live
		shell: map[string]bool{"alice": false},
	}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	g, _ := st.CreateGroup("Eltern", []string{"hp_hostek_power", "remshel:shell:access"})
	_ = st.SetUser("alice", UserConfig{Groups: []string{g.ID}})

	if err := m.Materialize("alice"); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 1 || ap.grants[0] != (grantCall{"hp_hostek_power", true}) {
		t.Errorf("expected one grant hp_hostek_power=on, got %v", ap.grants)
	}
	if len(ap.shells) != 1 || !ap.shells[0].on {
		t.Errorf("expected shell on, got %v", ap.shells)
	}
}

func TestMaterializeForceOffBeatsGroup(t *testing.T) {
	live := fakeLive{
		users: map[string]users.User{"alice": {Username: "alice", Groups: []string{"hp_hostek_power"}}},
	}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	g, _ := st.CreateGroup("Eltern", []string{"hp_hostek_power"})
	_ = st.SetUser("alice", UserConfig{Groups: []string{g.ID}, Overrides: map[string]string{"hp_hostek_power": "off"}})

	if err := m.Materialize("alice"); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 1 || ap.grants[0] != (grantCall{"hp_hostek_power", false}) {
		t.Errorf("force-off should revoke the group-granted right, got %v", ap.grants)
	}
}

func TestMaterializeNoChangeWhenInSync(t *testing.T) {
	live := fakeLive{
		users: map[string]users.User{"alice": {Username: "alice", Groups: []string{"hp_hostek_power"}}},
		shell: map[string]bool{"alice": false},
	}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	g, _ := st.CreateGroup("Eltern", []string{"hp_hostek_power"})
	_ = st.SetUser("alice", UserConfig{Groups: []string{g.ID}})
	if err := m.Materialize("alice"); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 0 || len(ap.shells) != 0 {
		t.Errorf("already-in-sync user should produce no wrapper calls, got grants=%v shells=%v", ap.grants, ap.shells)
	}
}

func TestMaterializeCollectsErrors(t *testing.T) {
	live := fakeLive{users: map[string]users.User{"alice": {Username: "alice"}}}
	ap := &fakeApplier{failGroup: "hp_hostek_power"}
	m, st := newTestMat(t, live, ap)
	// Two group rights to grant; one fails — the other must still be attempted.
	g, _ := st.CreateGroup("All", []string{"hp_hostek_power", "hp_samba_family_write"})
	_ = st.SetUser("alice", UserConfig{Groups: []string{g.ID}})

	err := m.Materialize("alice")
	if err == nil {
		t.Fatal("expected an aggregated error when a wrapper call fails")
	}
	if len(ap.grants) != 2 {
		t.Errorf("a single failure must not abort the rest: got %v", ap.grants)
	}
}

func TestReconcileInvitesAppliesToConsumer(t *testing.T) {
	live := fakeLive{
		users: map[string]users.User{"newbie": {Username: "newbie"}}, // managed, non-admin, no live rights
		shell: map[string]bool{"newbie": false},
	}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	g, _ := st.CreateGroup("Eltern", []string{"hp_hostek_power"})
	_ = st.SetInviteConfig("inv1", UserConfig{Groups: []string{g.ID}, Overrides: map[string]string{"remshel:shell:access": "on"}})

	lookup := func(id string) (string, bool) {
		if id == "inv1" {
			return "newbie", true
		}
		return "", false
	}
	// First pass: the config becomes the user's config and is materialized, but the invite copy
	// is kept for one more round (so a late grant_defaults can't undo it).
	if err := m.ReconcileInvites(lookup); err != nil {
		t.Fatal(err)
	}
	cfg, ok := st.GetUser("newbie")
	if !ok || len(cfg.Groups) != 1 || cfg.Overrides["remshel:shell:access"] != "on" {
		t.Errorf("invite config should become the user's config, got %+v ok=%v", cfg, ok)
	}
	if len(ap.grants) != 1 || ap.grants[0] != (grantCall{"hp_hostek_power", true}) {
		t.Errorf("expected hp_hostek_power granted, got %v", ap.grants)
	}
	if len(ap.shells) != 1 || !ap.shells[0].on {
		t.Errorf("expected shell on, got %v", ap.shells)
	}
	if _, ok := st.InviteConfig("inv1"); !ok {
		t.Error("invite config should be kept after the first pass (re-asserted next tick)")
	}
	// Second pass: re-assert, then drop so it can't apply again.
	if err := m.ReconcileInvites(lookup); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.InviteConfig("inv1"); ok {
		t.Error("invite config should be dropped after the second pass")
	}
}

func TestReconcileInvitesSkipsAndDrops(t *testing.T) {
	live := fakeLive{users: map[string]users.User{
		"adm":    {Username: "adm", IsAdmin: true},
		"hascfg": {Username: "hascfg"},
	}}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	_ = st.SetInviteConfig("admInv", UserConfig{Overrides: map[string]string{"hp_hostek_power": "on"}})
	_ = st.SetInviteConfig("cfgInv", UserConfig{Overrides: map[string]string{"hp_hostek_power": "on"}})
	_ = st.SetInviteConfig("pendInv", UserConfig{Overrides: map[string]string{"hp_hostek_power": "on"}})
	_ = st.SetInviteConfig("ghostInv", UserConfig{Overrides: map[string]string{"hp_hostek_power": "on"}})
	_ = st.SetUser("hascfg", UserConfig{Overrides: map[string]string{"hp_samba_family_write": "on"}})

	lookup := func(id string) (string, bool) {
		switch id {
		case "admInv":
			return "adm", true // consumer is admin → drop, never configure
		case "cfgInv":
			return "hascfg", true // already configured → drop, don't clobber
		case "pendInv":
			return "", true // not consumed yet → keep
		case "ghostInv":
			return "ghost", true // consumer not a managed account yet → keep
		}
		return "", false
	}
	if err := m.ReconcileInvites(lookup); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 0 {
		t.Errorf("no grants expected, got %v", ap.grants)
	}
	if _, ok := st.InviteConfig("admInv"); ok {
		t.Error("admin-consumer config should be dropped")
	}
	if _, ok := st.InviteConfig("cfgInv"); ok {
		t.Error("already-configured-consumer config should be dropped")
	}
	if _, ok := st.InviteConfig("pendInv"); !ok {
		t.Error("unconsumed invite config must be kept")
	}
	if _, ok := st.InviteConfig("ghostInv"); !ok {
		t.Error("config for a not-yet-created account must be kept")
	}
	// hascfg's own config must be untouched.
	cfg, _ := st.GetUser("hascfg")
	if cfg.Overrides["hp_samba_family_write"] != "on" {
		t.Errorf("existing config must not be clobbered, got %+v", cfg)
	}
}

func TestMaterializeAllBestEffort(t *testing.T) {
	live := fakeLive{users: map[string]users.User{
		"alice": {Username: "alice"},
		"bob":   {Username: "bob"},
	}}
	ap := &fakeApplier{}
	m, st := newTestMat(t, live, ap)
	g, _ := st.CreateGroup("Eltern", []string{"hp_hostek_power"})
	_ = st.SetUser("alice", UserConfig{Groups: []string{g.ID}})
	_ = st.SetUser("bob", UserConfig{Groups: []string{g.ID}})
	names := []string{"alice", "bob"}
	sort.Strings(names)
	if err := m.MaterializeAll(names); err != nil {
		t.Fatal(err)
	}
	if len(ap.grants) != 2 {
		t.Errorf("both users should be materialized, got %v", ap.grants)
	}
}
