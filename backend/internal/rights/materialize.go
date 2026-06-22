package rights

import (
	"fmt"
	"log"
	"sort"
	"sync"

	"privleg/internal/catalog"
	"privleg/internal/store"
	"privleg/internal/users"
)

// Live reads a user's current OS state. Abstracted so the materializer is testable without
// shelling out to id/getent.
type Live interface {
	Resolve(name string) users.User
	ShellEnabled(name string) bool
	IsManaged(name string) bool
}

// Applier performs the actual privileged mutations. Abstracted so tests can assert the
// wrapper calls without invoking sudo. The default wraps the store package.
type Applier interface {
	SetGrant(user, group string, on bool) error
	SetShell(user string, on bool) error
}

type liveOS struct{ ul *users.Lister }

func (l liveOS) Resolve(name string) users.User { return l.ul.Resolve(name) }
func (l liveOS) ShellEnabled(name string) bool  { return users.ShellEnabled(name) }
func (l liveOS) IsManaged(name string) bool     { return l.ul.IsManaged(name) }

type storeApplier struct{}

func (storeApplier) SetGrant(u, g string, on bool) error { return store.SetGrant(u, g, on) }
func (storeApplier) SetShell(u string, on bool) error    { return store.SetShell(u, on) }

// Materializer bridges the config layer to live Linux state: it resolves a user's effective
// rights and syncs their hp_* group membership + login shell to match, via the narrow root
// wrappers. Every materialize reconciles live state to config, so it also self-heals drift.
type Materializer struct {
	store  *Store
	cat    *catalog.Catalog
	live   Live
	apply  Applier
	syncMu sync.Mutex // serializes the read-live → diff → apply section across users
}

// NewMaterializer wires the production materializer (live OS reads + the store wrappers).
func NewMaterializer(st *Store, cat *catalog.Catalog, ul *users.Lister) *Materializer {
	return &Materializer{store: st, cat: cat, live: liveOS{ul}, apply: storeApplier{}}
}

// newMaterializer is the test seam (injectable Live + Applier).
func newMaterializer(st *Store, cat *catalog.Catalog, live Live, apply Applier) *Materializer {
	return &Materializer{store: st, cat: cat, live: live, apply: apply}
}

// heldRights returns the declared rights a user currently holds live: backing groups they
// belong to, plus every shell key when their login shell is enabled. Mirrors the API's
// rightsFor — it's the source of truth for the lazy migration baseline.
func (m *Materializer) heldRights(u users.User) []string {
	declaredGroups := map[string]bool{}
	var shellKeys []string
	for _, r := range m.cat.Rights() {
		if r.Kind == "shell" {
			shellKeys = append(shellKeys, r.Key)
		} else {
			declaredGroups[r.Key] = true
		}
	}
	out := []string{}
	for _, g := range u.Groups {
		if declaredGroups[g] {
			out = append(out, g)
		}
	}
	if m.live.ShellEnabled(u.Username) {
		out = append(out, shellKeys...)
	}
	sort.Strings(out)
	return out
}

// BaselineConfig returns a user's effective config WITHOUT persisting: the stored config if
// one exists, otherwise a synthetic baseline that reproduces their current live rights as
// explicit "on" overrides. This is the lazy-migration view — it lets the editor show an
// un-migrated user's real rights (all on), and gives putGrants a correct "before" to diff
// authorization against, so a user's first edit through privleg preserves what they have.
// Admins get an empty config (they hold everything implicitly and are never materialized).
func (m *Materializer) BaselineConfig(name string) UserConfig {
	if cfg, ok := m.store.GetUser(name); ok {
		return cfg
	}
	u := m.live.Resolve(name)
	cfg := UserConfig{Groups: []string{}, Overrides: map[string]string{}}
	if !u.IsAdmin {
		for _, key := range m.heldRights(u) {
			cfg.Overrides[key] = "on"
		}
	}
	return cfg
}

// materializableSet returns the set of right keys that currently can be synced down.
func (m *Materializer) materializableSet() (set map[string]bool, kind map[string]string) {
	set = map[string]bool{}
	kind = map[string]string{}
	for _, r := range m.cat.Rights() {
		set[r.Key] = true
		kind[r.Key] = r.Kind
	}
	return set, kind
}

// Materialize reconciles a user's live Linux group membership + login shell to their
// effective config. It is a no-op for admins and for users with no stored config (a
// never-configured user keeps whatever live groups they have — privleg never strips
// out-of-band memberships from someone it has never been asked to manage). Failures are
// collected (not fatal on the first one) so a single bad right can't wedge a bulk sync.
func (m *Materializer) Materialize(name string) error {
	u := m.live.Resolve(name)
	if u.IsAdmin {
		return nil
	}
	cfg, ok := m.store.GetUser(name)
	if !ok {
		return nil
	}
	set, kind := m.materializableSet()
	eff := Effective(cfg, m.store.ListGroups(), set)

	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	// Re-read live state right before diffing — it is the source of truth and lets the diff
	// self-heal any drift (e.g. a membership changed out-of-band).
	live := m.live.Resolve(name)
	current := map[string]bool{}
	for _, g := range live.Groups {
		if set[g] && kind[g] == "group" {
			current[g] = true
		}
	}
	shellOn := m.live.ShellEnabled(name)

	var errs []string

	// Group rights: one wrapper call per actual change.
	for key, want := range eff {
		if kind[key] != "group" {
			continue
		}
		if want != current[key] {
			if err := m.apply.SetGrant(name, key, want); err != nil {
				log.Printf("privleg: materialize %s grant %s=%v: %v", name, key, want, err)
				errs = append(errs, fmt.Sprintf("%s: %v", key, err))
			}
		}
	}

	// Shell rights: there is a single login shell, so OR every shell key's effective value
	// into one desired state and make at most one change.
	shellWant := false
	hasShell := false
	for key := range set {
		if kind[key] == "shell" {
			hasShell = true
			if eff[key] {
				shellWant = true
			}
		}
	}
	if hasShell && shellWant != shellOn {
		if err := m.apply.SetShell(name, shellWant); err != nil {
			log.Printf("privleg: materialize %s shell=%v: %v", name, shellWant, err)
			errs = append(errs, fmt.Sprintf("shell: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("materialize %s: %v", name, errs)
	}
	return nil
}

// InviteLookup reports the user who consumed an invite (its used_by, "" if not yet consumed)
// and whether the invite exists. A read failure should report exists=false so the reconciler
// leaves the config untouched and retries later — never drops it on a transient error.
type InviteLookup func(inviteID string) (usedBy string, exists bool)

// ReconcileInvites applies any pending invite rights configs, in two passes per invite so a
// late grant_defaults can't defeat it. For each stored invite config consumed by a now-existing,
// managed, non-admin user:
//   - first pass (user has no config yet): the invite config BECOMES the user's config and is
//     materialized — but the invite config is KEPT for one more round. The dashboard's
//     grant_defaults (which sets default-on rights, e.g. the login shell) runs unordered with
//     respect to this tick, so a single apply could be undone by a later grant_defaults.
//   - second pass (user's config still equals the invite config): re-materialize — now reliably
//     after grant_defaults — then drop the invite config.
//
// The config is dropped without applying when the consumer is an admin, or when the user's
// config differs from the invite config (an admin has since edited them — never clobber).
// Unconsumed / not-yet-created / momentarily-unreadable cases are left for the next run.
// Idempotent and safe on a timer.
func (m *Materializer) ReconcileInvites(lookup InviteLookup) error {
	var errs []string
	for _, id := range m.store.InviteConfigIDs() {
		cfg, ok := m.store.InviteConfig(id)
		if !ok {
			continue
		}
		usedBy, exists := lookup(id)
		if !exists || usedBy == "" {
			continue // not consumed yet (or store unreadable) — retry next run
		}
		if !m.live.IsManaged(usedBy) {
			continue // account not created yet — retry next run
		}
		if m.live.Resolve(usedBy).IsAdmin {
			_ = m.store.DeleteInviteConfig(id) // never configure admins
			continue
		}
		existing, has := m.store.GetUser(usedBy)
		if !has {
			// First pass: adopt the invite config as the user's config and materialize, but keep
			// the invite config one more round (see the two-pass note above).
			if err := m.store.SetUser(usedBy, cfg); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", usedBy, err))
				continue
			}
			if err := m.Materialize(usedBy); err != nil {
				log.Printf("privleg: materialize invite config for %s: %v", usedBy, err)
			}
			continue
		}
		if !configEqual(existing, cfg) {
			_ = m.store.DeleteInviteConfig(id) // admin has edited them — don't re-assert
			continue
		}
		// Second pass: re-assert (now reliably after grant_defaults), then drop.
		if err := m.Materialize(usedBy); err != nil {
			log.Printf("privleg: re-materialize invite config for %s: %v", usedBy, err)
		}
		_ = m.store.DeleteInviteConfig(id)
	}
	if len(errs) > 0 {
		return fmt.Errorf("reconcile invites: %v", errs)
	}
	return nil
}

// configEqual reports whether two configs are the same (groups compared as a set, overrides as
// a map) — used to tell "the user still has exactly the invite config we applied" from "an
// admin has since edited them".
func configEqual(a, b UserConfig) bool {
	if len(a.Overrides) != len(b.Overrides) {
		return false
	}
	for k, v := range a.Overrides {
		if b.Overrides[k] != v {
			return false
		}
	}
	ag := map[string]bool{}
	for _, g := range a.Groups {
		ag[g] = true
	}
	bg := map[string]bool{}
	for _, g := range b.Groups {
		bg[g] = true
	}
	if len(ag) != len(bg) {
		return false
	}
	for g := range ag {
		if !bg[g] {
			return false
		}
	}
	return true
}

// MaterializeAll reconciles many users, best-effort: every user is attempted even if some
// fail, and the per-user errors are aggregated. Used after a group definition changes.
func (m *Materializer) MaterializeAll(names []string) error {
	var errs []string
	for _, n := range names {
		if err := m.Materialize(n); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}
