package rights

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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

	g, err := s.CreateGroup("Eltern", []string{"hp_hostek_power", "remshel:shell:access"}, false)
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

	_, affected, err := s.UpdateGroup(g.ID, "Eltern+", []string{"hp_hostek_power"}, false)
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
	if slices.Contains(cfg.Groups, g.ID) {
		t.Error("deleting a group must strip it from every user's assignment")
	}
}

func TestUpdateDeleteUnknownGroup(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "rights.json"))
	if _, _, err := s.UpdateGroup("gen-deadbeef", "x", nil, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateGroup unknown = %v, want ErrNotFound", err)
	}
	if _, err := s.DeleteGroup("gen-deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteGroup unknown = %v, want ErrNotFound", err)
	}
}

func TestNewIDUnique(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "rights.json"))
	a, _ := s.CreateGroup("A", nil, false)
	b, _ := s.CreateGroup("B", nil, false)
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

func TestInviteConfigRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)
	if err := s.SetInviteConfig("inv1", UserConfig{Groups: []string{"g1"}, Overrides: map[string]string{"hp_x": "off"}}); err != nil {
		t.Fatal(err)
	}
	// Persists across reopen.
	s2, _ := Open(path)
	cfg, ok := s2.InviteConfig("inv1")
	if !ok || !slices.Contains(cfg.Groups, "g1") || cfg.Overrides["hp_x"] != "off" {
		t.Errorf("invite config roundtrip failed: %+v ok=%v", cfg, ok)
	}
	if ids := s2.InviteConfigIDs(); len(ids) != 1 || ids[0] != "inv1" {
		t.Errorf("InviteConfigIDs = %v, want [inv1]", ids)
	}
	if err := s2.DeleteInviteConfig("inv1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.InviteConfig("inv1"); ok {
		t.Error("invite config should be gone after delete")
	}
	if err := s2.DeleteInviteConfig("missing"); err != nil {
		t.Errorf("deleting a missing invite config must be a no-op: %v", err)
	}
}

// TestSaveLeavesNoTornOrTempFile pins the atomic-write contract: after a committed mutation
// the destination is a complete, parseable snapshot and no ".tmp" sidecar survives — a reader
// arriving at any moment sees whole JSON, never a truncated in-between.
func TestSaveLeavesNoTornOrTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rights.json")
	s, _ := Open(path)
	if _, err := s.CreateGroup("Team", []string{"hp_x"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a committed save must not leave a temp sidecar behind (stat err = %v)", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Errorf("persisted file is not complete, valid JSON: %v", err)
	}
	if len(st.Groups) != 1 {
		t.Errorf("persisted state should hold the one group, got %d", len(st.Groups))
	}
}

// TestSaveOverwritesStaleTempFile ensures a temp file left behind by a crashed earlier write
// (fixed ".tmp" name) can never corrupt the next save: it is truncated + reused and the commit
// still yields exactly the new state.
func TestSaveOverwritesStaleTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rights.json")
	if err := os.WriteFile(path+".tmp", []byte("garbage-not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := Open(path)
	if _, err := s.CreateGroup("Team", nil, false); err != nil {
		t.Fatalf("a stale temp file must not break the next save: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("stale temp should be consumed by the atomic rename, stat err = %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after stale-temp save: %v", err)
	}
	if len(s2.ListGroups()) != 1 {
		t.Errorf("committed state should have 1 group, got %d", len(s2.ListGroups()))
	}
}

// TestAdoptUserConfig pins the compare-and-set contract: adopt only when the user is absent,
// never clobber an existing config, always hand back a deep copy of the config now in force.
func TestAdoptUserConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)

	// Absent → adopts, reports adopted, persists.
	cur, adopted, err := s.AdoptUserConfig("newbie", UserConfig{Overrides: map[string]string{"hp_x": "on"}})
	if err != nil {
		t.Fatal(err)
	}
	if !adopted {
		t.Fatal("adopting an absent user must report adopted=true")
	}
	if cur.Overrides["hp_x"] != "on" {
		t.Errorf("adopt must return the in-force config, got %+v", cur)
	}
	if cfg, ok := s.GetUser("newbie"); !ok || cfg.Overrides["hp_x"] != "on" {
		t.Errorf("adopted config must be persisted, got %+v ok=%v", cfg, ok)
	}

	// Present → does NOT clobber, reports not adopted, returns the EXISTING config.
	cur, adopted, err = s.AdoptUserConfig("newbie", UserConfig{Overrides: map[string]string{"hp_x": "off"}})
	if err != nil {
		t.Fatal(err)
	}
	if adopted {
		t.Error("adopt must not overwrite an already-configured user")
	}
	if cur.Overrides["hp_x"] != "on" {
		t.Errorf("adopt must return the pre-existing config, got %+v", cur)
	}
	if cfg, _ := s.GetUser("newbie"); cfg.Overrides["hp_x"] != "on" {
		t.Errorf("existing config must remain untouched, got %+v", cfg)
	}

	// The returned config is a deep copy — mutating it must not corrupt the store.
	cur.Overrides["hp_x"] = "mutated"
	if cfg, _ := s.GetUser("newbie"); cfg.Overrides["hp_x"] != "on" {
		t.Error("AdoptUserConfig must return a deep copy, not an alias into the store")
	}
}

// TestConcurrentAdoptElectsExactlyOneWriter exercises the atomicity axiom directly: many
// goroutines race to adopt the SAME user, each with a distinct config. Compare-and-set under one
// lock must elect exactly one adopter; every other caller must observe a whole config (never a
// torn or half-applied one), and the persisted file must stay complete, valid JSON. Run -race.
func TestConcurrentAdoptElectsExactlyOneWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)

	const goroutines = 32
	var wg sync.WaitGroup
	var adoptedCount int64
	winner := make(chan string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			val := "v" + strconv.Itoa(i)
			cur, adopted, err := s.AdoptUserConfig("racer", UserConfig{Overrides: map[string]string{"k": val}})
			if err != nil {
				t.Errorf("adopt: %v", err)
				return
			}
			if adopted {
				atomic.AddInt64(&adoptedCount, 1)
				winner <- val
			}
			// Winner or not, every caller must see a fully-formed config, never an empty/torn one.
			if cur.Overrides["k"] == "" {
				t.Errorf("adopt returned an incomplete config: %+v", cur)
			}
		}(i)
	}
	wg.Wait()
	close(winner)
	if adoptedCount != 1 {
		t.Fatalf("exactly one goroutine may adopt, got %d", adoptedCount)
	}
	won := <-winner
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("persisted file must stay valid JSON under concurrency: %v", err)
	}
	if got := st.Users["racer"].Overrides["k"]; got != won {
		t.Errorf("persisted config = %q, want the elected winner %q", got, won)
	}
}

// TestConcurrentMixedWritesStayConsistent hammers the store with different mutating methods from
// many goroutines at once; the single mutex must serialize every writer so the on-disk file is
// never observed torn and always reopens cleanly. Run under -race to catch unsynchronized access.
func TestConcurrentMixedWritesStayConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rights.json")
	s, _ := Open(path)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				_, _ = s.CreateGroup("g"+strconv.Itoa(i), []string{"hp_x"}, false)
			case 1:
				_ = s.SetUser("u"+strconv.Itoa(i), UserConfig{Overrides: map[string]string{"hp_x": "on"}})
			case 2:
				_ = s.SetInviteConfig("inv"+strconv.Itoa(i), UserConfig{Groups: []string{"g"}})
			case 3:
				_, _, _ = s.AdoptUserConfig("a"+strconv.Itoa(i), UserConfig{Overrides: map[string]string{"hp_y": "off"}})
			}
		}(i)
	}
	wg.Wait()
	// Whatever the interleaving, the persisted file must be one valid snapshot that reopens cleanly.
	if _, err := Open(path); err != nil {
		t.Fatalf("store must reopen after concurrent writes: %v", err)
	}
	b, _ := os.ReadFile(path)
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("persisted file must stay valid JSON under concurrency: %v", err)
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
