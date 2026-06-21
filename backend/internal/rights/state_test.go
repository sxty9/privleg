package rights

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

func TestOpenMissingFileIsEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "rights.json"))
	if err != nil {
		t.Fatalf("Open of a missing file should not error: %v", err)
	}
	if len(s.ListGroups()) != 0 {
		t.Error("a fresh store has no groups")
	}
	if _, ok := s.GetUser("alice"); ok {
		t.Error("a fresh store has no configured users")
	}
}

func TestGroupCRUDAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)

	g, err := s.CreateGroup("Eltern", []string{"hp_hostek_power", "remshel:shell:access"})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^gen-[0-9a-f]{8}$`).MatchString(g.ID) {
		t.Errorf("group id %q does not match the expected format", g.ID)
	}

	// Assign a user, then verify update/delete report them as affected.
	if err := s.SetUser("alice", UserConfig{Groups: []string{g.ID}}); err != nil {
		t.Fatal(err)
	}

	_, affected, err := s.UpdateGroup(g.ID, "Eltern+", []string{"hp_hostek_power"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect_equalStrings(affected, []string{"alice"}) {
		t.Errorf("UpdateGroup affected = %v, want [alice]", affected)
	}

	// Persistence: reopen and confirm the group survived with its new label.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Group(g.ID)
	if !ok || got.Label != "Eltern+" {
		t.Errorf("reopened group = %+v, ok=%v; want label Eltern+", got, ok)
	}

	// Delete strips the assignment and reports the affected user.
	affected, err = s2.DeleteGroup(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect_equalStrings(affected, []string{"alice"}) {
		t.Errorf("DeleteGroup affected = %v, want [alice]", affected)
	}
	cfg, _ := s2.GetUser("alice")
	if contains(cfg.Groups, g.ID) {
		t.Error("deleting a group must strip it from every user's assignment")
	}
}

func TestUpdateDeleteUnknownGroup(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "rights.json"))
	if _, _, err := s.UpdateGroup("gen-deadbeef", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateGroup unknown = %v, want ErrNotFound", err)
	}
	if _, err := s.DeleteGroup("gen-deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteGroup unknown = %v, want ErrNotFound", err)
	}
}

func TestNewIDUnique(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "rights.json"))
	a, _ := s.CreateGroup("A", nil)
	b, _ := s.CreateGroup("B", nil)
	if a.ID == b.ID {
		t.Error("generated group ids must be unique")
	}
}

func TestSetUserNormalizesAndRoundtrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)
	if err := s.SetUser("bob", UserConfig{Overrides: map[string]string{"hp_x": "off"}}); err != nil {
		t.Fatal(err)
	}
	s2, _ := Open(path)
	cfg, ok := s2.GetUser("bob")
	if !ok {
		t.Fatal("bob should be persisted")
	}
	if cfg.Groups == nil {
		t.Error("Groups should be normalized to an empty (non-nil) slice")
	}
	if cfg.Overrides["hp_x"] != "off" {
		t.Errorf("override roundtrip failed: %v", cfg.Overrides)
	}
}

func TestDeleteUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)
	if err := s.SetUser("carol", UserConfig{Overrides: map[string]string{"hp_x": "on"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("carol"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetUser("carol"); ok {
		t.Error("config should be gone after DeleteUser")
	}
	if err := s.DeleteUser("nobody"); err != nil {
		t.Errorf("deleting a missing user must be a no-op, got %v", err)
	}
	// Deletion persists across reopen.
	s2, _ := Open(path)
	if _, ok := s2.GetUser("carol"); ok {
		t.Error("deletion must persist")
	}
}

func reflect_equalStrings(a, b []string) bool {
	a = append([]string{}, a...)
	b = append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
