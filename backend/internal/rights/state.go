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
// /var/lib/privleg and reads+writes rights.json directly, atomically and durably (fsync'd
// temp + rename within the same dir, since PrivateTmp puts /tmp elsewhere — see
// writeFileAtomic). A single process is the only writer, so an in-memory snapshot guarded by
// one mutex is the whole concurrency story.
package rights

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// DefaultPath is where privlegd keeps the rights config layer (privleg's own home).
const DefaultPath = "/var/lib/privleg/rights.json"

// ErrNotFound is returned when a group id does not exist.
var ErrNotFound = errors.New("rights: group not found")

// Group is an admin-defined group. Primarily a named bundle of declared rights (catalog keys —
// a backing hp_* group, or a shell key "svc:cat:id"), it may ALSO define contact visibility: one
// group definition carries both functions (e.g. "Developer" grants dev rights AND makes its members
// mutual contacts). A group may be rights-only, contact-only, or both.
type Group struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Rights []string `json:"rights"`
	// ContactVisibility turns this group into a contact web: privleg materialises a backing
	// hc_<id> Linux group whose members are the participating (non-opted-out) assignees, and the
	// contax service reads that group live to make those members see each other as contacts.
	ContactVisibility bool `json:"contactVisibility,omitempty"`
}

// UserConfig is one user's rights configuration: the groups they belong to, plus per-right
// manual overrides. An override "on" forces the right granted, "off" forces it denied; a
// right with no override inherits from the assigned groups (the "Gruppe" state).
type UserConfig struct {
	Groups    []string          `json:"groups"`
	Overrides map[string]string `json:"overrides"`
	// ContactOptOut lists ids of contact-visibility groups this user is assigned to but is excluded
	// from the contact web of (Model B: visibility decoupled from rights, so a member can keep a
	// group's rights without appearing to the others). Default empty ⇒ participate in every assigned
	// contact group.
	ContactOptOut []string `json:"contactOptOut,omitempty"`
}

// State is the entire persisted config layer.
type State struct {
	Groups []Group               `json:"groups"`
	Users  map[string]UserConfig `json:"users"`
	// InviteConfigs holds the rights config an admin attached to an invite, keyed by invite
	// id. The reconciler copies it onto whoever consumes the invite, then drops it.
	InviteConfigs map[string]UserConfig `json:"inviteConfigs,omitempty"`
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

// save writes the current state atomically and durably. The caller must hold s.mu.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o600)
}

// writeFileAtomic writes data to path so that neither a concurrent reader nor a crash can
// ever observe a half-written file. It writes a sibling temp file, fsyncs it so the bytes
// reach disk BEFORE the file becomes visible, atomically renames it over path (POSIX rename
// is atomic), then best-effort fsyncs the directory so the rename itself survives a crash.
// Either the whole previous file or the whole new file is ever observable — never a truncated
// or zero-length in-between.
//
// A plain WriteFile+Rename gives the atomic *swap* but not durability: a crash right after
// the rename could surface a zero-length rights.json, an observable intermediate state the
// store must never persist. The temp file is removed if anything fails before the rename
// commits, so a failed write leaves the previous file untouched (the callers' rollback of the
// in-memory snapshot then restores the match).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Best-effort: fsync the directory so the rename (the actual commit) is durable. Not every
	// filesystem supports directory fsync, and a failure here does not undo the atomic replace,
	// so it is deliberately non-fatal.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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
func (s *Store) CreateGroup(label string, rightsKeys []string, contactVisibility bool) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := Group{ID: s.newID(), Label: label, Rights: append([]string{}, rightsKeys...), ContactVisibility: contactVisibility}
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
func (s *Store) UpdateGroup(id, label string, rightsKeys []string, contactVisibility bool) (Group, []string, error) {
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
	s.st.Groups[idx] = Group{ID: id, Label: label, Rights: append([]string{}, rightsKeys...), ContactVisibility: contactVisibility}
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
		newUsers[name] = UserConfig{Groups: without(cfg.Groups, id), Overrides: cfg.Overrides, ContactOptOut: without(cfg.ContactOptOut, id)}
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

// SetUser stores a user's config and persists. Nil slices/maps are normalized to empty so the
// on-disk JSON is stable — that normalization lives in cloneConfig, the single place both write
// paths (here and AdoptUserConfig) route through, so they can never drift apart.
func (s *Store) SetUser(name string, cfg UserConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.st.Users[name]
	s.st.Users[name] = cloneConfig(cfg)
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

// AdoptUserConfig atomically installs cfg as name's configuration, but ONLY if name has no
// stored configuration yet; it reports whether it did and returns the configuration now in
// force. It is the store's compare-and-set: the invite reconciler must read "is this user
// already configured?" and, only if not, adopt the invite config — as one indivisible step.
// Split into a separate GetUser + SetUser, a concurrent admin edit landing between the two
// would be silently clobbered (the reconciler reverting an admin's fresh config back to the
// invite defaults) — exactly the observable intermediate state the atomicity axiom forbids.
// Returning the in-force config lets the caller decide its next move without a second, racy read.
func (s *Store) AdoptUserConfig(name string, cfg UserConfig) (UserConfig, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.st.Users[name]; ok {
		return cloneConfig(existing), false, nil
	}
	norm := cloneConfig(cfg)
	s.st.Users[name] = norm
	if err := s.save(); err != nil {
		delete(s.st.Users, name)
		return UserConfig{}, false, err
	}
	return cloneConfig(norm), true, nil
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

// SetInviteConfig stores the rights config attached to an invite (keyed by invite id).
func (s *Store) SetInviteConfig(inviteID string, cfg UserConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.InviteConfigs == nil {
		s.st.InviteConfigs = map[string]UserConfig{}
	}
	prev, had := s.st.InviteConfigs[inviteID]
	s.st.InviteConfigs[inviteID] = cloneConfig(cfg)
	if err := s.save(); err != nil {
		if had {
			s.st.InviteConfigs[inviteID] = prev
		} else {
			delete(s.st.InviteConfigs, inviteID)
		}
		return err
	}
	return nil
}

// InviteConfig returns the config attached to an invite (deep copy) and whether one exists.
func (s *Store) InviteConfig(inviteID string) (UserConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.st.InviteConfigs[inviteID]
	if !ok {
		return UserConfig{}, false
	}
	return cloneConfig(cfg), true
}

// DeleteInviteConfig drops an invite's config (after it's been applied, or on revoke). No-op
// if absent.
func (s *Store) DeleteInviteConfig(inviteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.st.InviteConfigs[inviteID]
	if !ok {
		return nil
	}
	delete(s.st.InviteConfigs, inviteID)
	if err := s.save(); err != nil {
		s.st.InviteConfigs[inviteID] = prev
		return err
	}
	return nil
}

// InviteConfigIDs returns the invite ids that currently carry a config (snapshot).
func (s *Store) InviteConfigIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.st.InviteConfigs))
	for id := range s.st.InviteConfigs {
		out = append(out, id)
	}
	return out
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
	return Group{ID: g.ID, Label: g.Label, Rights: append([]string{}, g.Rights...), ContactVisibility: g.ContactVisibility}
}

func cloneGroups(gs []Group) []Group {
	out := make([]Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, cloneGroup(g))
	}
	return out
}

func cloneConfig(c UserConfig) UserConfig {
	out := UserConfig{Groups: append([]string{}, c.Groups...), Overrides: map[string]string{}, ContactOptOut: append([]string{}, c.ContactOptOut...)}
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
