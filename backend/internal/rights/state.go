// Package rights is privleg's rights-groups config layer: the only state privleg owns
// beyond live Linux groups. Admins define rights GROUPS (named bundles of declared rights)
// and assign users to them; a user inherits a right if any assigned group grants it, and
// may override any single right on/off. This package PERSISTS that configuration; the
// materializer (materialize.go) resolves it to an effective set and syncs it down to live
// Linux group membership + login shell via the existing privleg-grant/privleg-set-shell
// wrappers. Enforcement everywhere else still reads live Linux groups — this layer is
// invisible to every other service.
//
// The store is privleg-private (unlike the shared invite store): privlegd owns
// /var/lib/privleg and reads+writes rights.json directly, atomically (temp + rename within
// the same dir, since PrivateTmp puts /tmp elsewhere). A single process is the only writer,
// so an in-memory snapshot guarded by one mutex is the whole concurrency story.
package rights

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// DefaultPath is where privlegd keeps the rights config layer (privleg's own home).
const DefaultPath = "/var/lib/privleg/rights.json"

// ErrNotFound is returned when a group id does not exist.
var ErrNotFound = errors.New("rights: group not found")

// Group is an admin-defined rights group: a named bundle of declared rights. Rights are
// catalog keys — a backing hp_* group, or a shell key "svc:cat:id".
type Group struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Rights []string `json:"rights"`
}

// UserConfig is one user's rights configuration: the groups they belong to, plus per-right
// manual overrides. An override "on" forces the right granted, "off" forces it denied; a
// right with no override inherits from the assigned groups (the "Gruppe" state).
type UserConfig struct {
	Groups    []string          `json:"groups"`
	Overrides map[string]string `json:"overrides"`
}

// State is the entire persisted config layer.
type State struct {
	Groups []Group               `json:"groups"`
	Users  map[string]UserConfig `json:"users"`
}

// Store is the atomic, in-memory-cached persistence for State. privlegd is the only writer.
type Store struct {
	path string
	mu   sync.Mutex
	st   State
}

// Open loads the store from path (DefaultPath if empty). A missing file is not an error —
// it means "no groups, no configured users" (first run / fresh install), mirroring how the
// catalog and invite store treat absent inputs.
func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath
	}
	s := &Store{path: path, st: State{Users: map[string]UserConfig{}}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Users == nil {
		st.Users = map[string]UserConfig{}
	}
	s.st = st
	return s, nil
}

// save writes the current state atomically. The caller must hold s.mu.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ListGroups returns a deep copy of all groups.
func (s *Store) ListGroups() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneGroups(s.st.Groups)
}

// Group returns one group by id (deep copy) and whether it exists.
func (s *Store) Group(id string) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.st.Groups {
		if g.ID == id {
			return cloneGroup(g), true
		}
	}
	return Group{}, false
}

// CreateGroup appends a new group with a freshly generated id and persists it.
func (s *Store) CreateGroup(label string, rightsKeys []string) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := Group{ID: s.newID(), Label: label, Rights: append([]string{}, rightsKeys...)}
	s.st.Groups = append(s.st.Groups, g)
	if err := s.save(); err != nil {
		// roll back the in-memory append so a failed write doesn't leave a phantom group.
		s.st.Groups = s.st.Groups[:len(s.st.Groups)-1]
		return Group{}, err
	}
	return cloneGroup(g), nil
}

// UpdateGroup replaces a group's label + rights, persists, and returns the updated group
// plus the usernames currently assigned to it (so the caller can re-materialize them).
func (s *Store) UpdateGroup(id, label string, rightsKeys []string) (Group, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, g := range s.st.Groups {
		if g.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Group{}, nil, ErrNotFound
	}
	prev := s.st.Groups[idx]
	s.st.Groups[idx] = Group{ID: id, Label: label, Rights: append([]string{}, rightsKeys...)}
	if err := s.save(); err != nil {
		s.st.Groups[idx] = prev
		return Group{}, nil, err
	}
	return cloneGroup(s.st.Groups[idx]), s.membersOf(id), nil
}

// DeleteGroup removes a group and strips its id from every user's assignment list. It
// returns the usernames that were assigned (so they can be re-materialized) and persists.
func (s *Store) DeleteGroup(id string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, g := range s.st.Groups {
		if g.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotFound
	}
	affected := s.membersOf(id)
	// snapshot for rollback
	prevGroups := s.st.Groups
	prevUsers := s.st.Users

	s.st.Groups = append(append([]Group{}, s.st.Groups[:idx]...), s.st.Groups[idx+1:]...)
	newUsers := make(map[string]UserConfig, len(s.st.Users))
	for name, cfg := range s.st.Users {
		newUsers[name] = UserConfig{Groups: without(cfg.Groups, id), Overrides: cfg.Overrides}
	}
	s.st.Users = newUsers
	if err := s.save(); err != nil {
		s.st.Groups, s.st.Users = prevGroups, prevUsers
		return nil, err
	}
	return affected, nil
}

// GetUser returns a user's config (deep copy) and whether one is stored.
func (s *Store) GetUser(name string) (UserConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.st.Users[name]
	if !ok {
		return UserConfig{}, false
	}
	return cloneConfig(cfg), true
}

// SetUser stores a user's config and persists. Nil slices/maps are normalized to empty so
// the on-disk JSON is stable.
func (s *Store) SetUser(name string, cfg UserConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.st.Users[name]
	norm := UserConfig{Groups: append([]string{}, cfg.Groups...), Overrides: map[string]string{}}
	for k, v := range cfg.Overrides {
		norm.Overrides[k] = v
	}
	if norm.Groups == nil {
		norm.Groups = []string{}
	}
	s.st.Users[name] = norm
	if err := s.save(); err != nil {
		if had {
			s.st.Users[name] = prev
		} else {
			delete(s.st.Users, name)
		}
		return err
	}
	return nil
}

// DeleteUser drops a user's stored config (e.g. when their account is deleted), so a later
// same-name account never inherits stale assignments/overrides. A missing entry is a no-op.
func (s *Store) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.st.Users[name]
	if !ok {
		return nil
	}
	delete(s.st.Users, name)
	if err := s.save(); err != nil {
		s.st.Users[name] = prev
		return err
	}
	return nil
}

// membersOf returns the usernames assigned to a group id. Caller must hold s.mu.
func (s *Store) membersOf(id string) []string {
	var out []string
	for name, cfg := range s.st.Users {
		if contains(cfg.Groups, id) {
			out = append(out, name)
		}
	}
	return out
}

// newID returns a fresh, unique opaque group id. Caller must hold s.mu.
func (s *Store) newID() string {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			// rand should never fail; if it does, fall back to a counter-ish id so we still
			// return something valid rather than panicking the request.
			b = [4]byte{byte(len(s.st.Groups)), 0, 0, 0}
		}
		id := "gen-" + hex.EncodeToString(b[:])
		exists := false
		for _, g := range s.st.Groups {
			if g.ID == id {
				exists = true
				break
			}
		}
		if !exists {
			return id
		}
	}
}

// --- value helpers (deep copies keep callers from aliasing internal state) ---

func cloneGroup(g Group) Group {
	return Group{ID: g.ID, Label: g.Label, Rights: append([]string{}, g.Rights...)}
}

func cloneGroups(gs []Group) []Group {
	out := make([]Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, cloneGroup(g))
	}
	return out
}

func cloneConfig(c UserConfig) UserConfig {
	out := UserConfig{Groups: append([]string{}, c.Groups...), Overrides: map[string]string{}}
	for k, v := range c.Overrides {
		out.Overrides[k] = v
	}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func without(xs []string, drop string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}
