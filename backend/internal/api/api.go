// Package api serves privleg's HTTP surface under /api/services/privleg/, behind the
// shared holistic session. privleg is the management plane for the holistic rights
// standard: it lists users, aggregates every service's declared rights, and toggles a
// user's rights (Linux group membership) or admin status — always via the narrow root
// wrappers. Enforcement of the rights themselves lives in each service, not here.
//
// Authorization:
//   - admins may do everything;
//   - a delegated manager (non-admin with hp_priv_dlg_<service>) may set THAT service's
//     rights for other users, but never admin status and never privleg's own meta-rights;
//   - admin status is toggled by admins only, and never on your own account.
package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"privleg/internal/auth"
	"privleg/internal/catalog"
	"privleg/internal/invites"
	"privleg/internal/rights"
	"privleg/internal/store"
	"privleg/internal/users"
)

const base = "/api/services/privleg/"

const (
	privService = "privleg"      // privleg's own manifest service id (self-reference)
	dlgPrefix   = "hp_priv_dlg_" // hp_priv_dlg_<service> = "may manage <service> rights for others"
	viewGroup   = "hp_priv_view" // may view the user list + rights, without changing them
	inviteGroup = "hp_priv_invite"

	noteMax = 200 // cap the user-supplied invite note before it reaches the store
	daysMax = 3650
)

var (
	userRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	inviteIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`) // holistic-invites.py ids are token_hex(4)
	groupIDRe  = regexp.MustCompile(`^gen-[0-9a-f]{8}$`)
)

const labelMax = 64 // cap a rights-group label before it reaches the store

// Server wires the verifier, catalog, user lister and rights config store into HTTP handlers.
type Server struct {
	v   *auth.Verifier
	cat *catalog.Catalog
	ul  *users.Lister
	rs  *rights.Store
	mat *rights.Materializer
}

// New builds a server.
func New(v *auth.Verifier, cat *catalog.Catalog, ul *users.Lister, rs *rights.Store, mat *rights.Materializer) *Server {
	return &Server{v: v, cat: cat, ul: ul, rs: rs, mat: mat}
}

type handler func(w http.ResponseWriter, r *http.Request, u *auth.User)

// Handler returns the routed http.Handler (Go 1.22 method+path patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"users", s.guard(s.isManager, false, s.listUsers))
	mux.HandleFunc("GET "+base+"catalog", s.guard(s.isManager, false, s.getCatalog))
	mux.HandleFunc("GET "+base+"users/{username}/grants", s.guard(s.isManager, false, s.getGrants))
	mux.HandleFunc("PUT "+base+"users/{username}/grants", s.guard(s.isManager, true, s.putGrants))
	mux.HandleFunc("PUT "+base+"users/{username}/admin", s.guard(isAdmin, true, s.setAdmin))
	mux.HandleFunc("DELETE "+base+"users/{username}", s.guard(isAdmin, true, s.deleteUser))
	// Rights groups: reading is for any console manager (the editor shows assignments);
	// defining/assigning groups is admin-only (a group can bundle cross-service rights).
	mux.HandleFunc("GET "+base+"groups", s.guard(s.isManager, false, s.listGroups))
	mux.HandleFunc("POST "+base+"groups", s.guard(isAdmin, true, s.createGroup))
	mux.HandleFunc("PUT "+base+"groups/{id}", s.guard(isAdmin, true, s.updateGroup))
	mux.HandleFunc("DELETE "+base+"groups/{id}", s.guard(isAdmin, true, s.deleteGroup))
	mux.HandleFunc("GET "+base+"invites", s.guard(s.canInvite, false, s.listInvites))
	mux.HandleFunc("POST "+base+"invites", s.guard(s.canInvite, true, s.createInvite))
	mux.HandleFunc("POST "+base+"invites/{id}/revoke", s.guard(s.canInvite, true, s.revokeInvite))
	mux.HandleFunc("POST "+base+"refresh", s.guard(isAdmin, false, s.refresh))
	mux.HandleFunc("GET "+base+"health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

// guard authenticates, applies an authorization gate, and optionally enforces CSRF.
func (s *Server) guard(gate func(*auth.User) bool, csrf bool, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.v.User(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "Not authenticated")
			return
		}
		if gate != nil && !gate(u) {
			writeErr(w, http.StatusForbidden, "You do not have permission for this action")
			return
		}
		if csrf && !s.v.CheckCSRF(r) {
			writeErr(w, http.StatusForbidden, "CSRF check failed")
			return
		}
		h(w, r, u)
	}
}

// --- authorization gates -------------------------------------------------

func isAdmin(u *auth.User) bool { return u.IsAdmin }

// isManager: admins, the view right, or any delegated manager may read the console.
func (s *Server) isManager(u *auth.User) bool {
	if u.IsAdmin {
		return true
	}
	for _, g := range u.Groups {
		if g == viewGroup || strings.HasPrefix(g, dlgPrefix) {
			return true
		}
	}
	return false
}

// canManageService: may the caller change rights of service svc for OTHER users?
// privleg's own meta-rights are admin-only (a delegated manager can't escalate delegation).
func (s *Server) canManageService(u *auth.User, svc string) bool {
	if u.IsAdmin {
		return true
	}
	if svc == privService {
		return false
	}
	return contains(u.Groups, dlgPrefix+svc)
}

// --- handlers ------------------------------------------------------------

type userOut struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	IsAdmin     bool     `json:"isAdmin"`
	Rights      []string `json:"rights"` // declared rights groups the user currently holds
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	all := s.ul.List()
	out := make([]userOut, 0, len(all))
	for _, u := range all {
		out = append(out, userOut{u.Username, u.DisplayName, u.IsAdmin, s.rightsFor(u)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// rightsFor returns the declared rights a user currently holds: the backing groups they
// belong to, plus any shell-permission keys when their login shell is enabled (the single
// source of truth). Shell perms have no group, so they are reported by their "svc:cat:id".
func (s *Server) rightsFor(u users.User) []string {
	out := filterDeclared(u.Groups, s.cat.DeclaredSet())
	if shellSet := s.cat.ShellPermSet(); len(shellSet) > 0 && users.ShellEnabled(u.Username) {
		for k := range shellSet {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// outFor builds the per-user response (identity + currently held rights).
func (s *Server) outFor(name string) userOut {
	u := s.ul.Resolve(name)
	return userOut{u.Username, u.DisplayName, u.IsAdmin, s.rightsFor(u)}
}

func (s *Server) getCatalog(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	// Re-read the drop-in directory so rights a service just installed or updated show up
	// live — without needing a privleg restart or a manual refresh. Best-effort: on a read
	// error the last-good catalog is kept.
	_ = s.cat.Reload()
	writeJSON(w, http.StatusOK, map[string]any{"services": s.cat.Manifests()})
}

// grantsResp is the per-user rights view. `groups` are the assigned rights-group ids;
// `overrides` are the per-right manual deviations (on/off); `inherited` are the rights the
// assigned groups grant (ignoring overrides) — the UI uses it to label the "Gruppe" segment;
// `effective` is the fully resolved set actually enforced.
type grantsResp struct {
	Username    string            `json:"username"`
	DisplayName string            `json:"displayName"`
	IsAdmin     bool              `json:"isAdmin"`
	Groups      []string          `json:"groups"`
	Overrides   map[string]string `json:"overrides"`
	Inherited   []string          `json:"inherited"`
	Effective   []string          `json:"effective"`
}

// materializableSet is the set of right keys that currently can be synced down (every
// declared backing-group right + shell right).
func (s *Server) materializableSet() map[string]bool {
	set := map[string]bool{}
	for _, r := range s.cat.Rights() {
		set[r.Key] = true
	}
	return set
}

// grantsFor builds the per-user rights view from the (possibly synthetic) baseline config.
func (s *Server) grantsFor(name string) grantsResp {
	u := s.ul.Resolve(name)
	cfg := s.mat.BaselineConfig(name)
	set := s.materializableSet()
	groups := s.rs.ListGroups()
	if cfg.Groups == nil {
		cfg.Groups = []string{}
	}
	if cfg.Overrides == nil {
		cfg.Overrides = map[string]string{}
	}
	return grantsResp{
		Username:    u.Username,
		DisplayName: u.DisplayName,
		IsAdmin:     u.IsAdmin,
		Groups:      cfg.Groups,
		Overrides:   cfg.Overrides,
		Inherited:   trueKeys(rights.InheritedRights(cfg, groups, set)),
		Effective:   trueKeys(rights.Effective(cfg, groups, set)),
	}
}

func (s *Server) getGrants(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	name := r.PathValue("username")
	if !userRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Invalid username")
		return
	}
	if !s.ul.IsManaged(name) {
		writeErr(w, http.StatusNotFound, "Unknown user")
		return
	}
	writeJSON(w, http.StatusOK, s.grantsFor(name))
}

// putGrants sets a user's rights configuration: the submitted body is the COMPLETE desired
// {groups, overrides}. We diff it against the user's current baseline (stored config, or a
// synthetic snapshot of their live rights for a not-yet-migrated user) and authorize each
// kind of change before applying ANY (no partial escalation):
//   - any change to group ASSIGNMENT is admin-only (a group can bundle cross-service rights);
//   - each changed per-right OVERRIDE needs the same per-service right as before
//     (canManageService) — a delegated manager keeps fine control of its own service.
//
// The desired config is then persisted and materialized down to live Linux state.
func (s *Server) putGrants(w http.ResponseWriter, r *http.Request, caller *auth.User) {
	name := r.PathValue("username")
	if !userRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Invalid username")
		return
	}
	if !s.ul.IsManaged(name) {
		writeErr(w, http.StatusNotFound, "Unknown user")
		return
	}
	// Refuse to write a rights config for an admin target. Admins hold everything implicitly
	// and are never materialized, so editing their config is meaningless — and allowing it
	// would let a manager pre-stage overrides on an admin that lie dormant (empty baseline)
	// and then silently materialize if the account is later de-admined. The UI never opens
	// the editor for admins; this is the matching server-side guard.
	if s.ul.Resolve(name).IsAdmin {
		writeErr(w, http.StatusBadRequest, "Cannot edit the rights of an admin")
		return
	}
	var body struct {
		Groups    []string          `json:"groups"`
		Overrides map[string]string `json:"overrides"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if body.Overrides == nil {
		body.Overrides = map[string]string{}
	}
	if body.Groups == nil {
		body.Groups = []string{}
	}

	// Validate the desired override keys (declared) and values (on/off).
	set := s.materializableSet()
	for key, val := range body.Overrides {
		if !set[key] {
			writeErr(w, http.StatusBadRequest, "Unknown right: "+key)
			return
		}
		if val != "on" && val != "off" {
			writeErr(w, http.StatusBadRequest, "Override must be on or off")
			return
		}
	}
	// Validate the desired group ids exist.
	groupSet := map[string]bool{}
	for _, g := range s.rs.ListGroups() {
		groupSet[g.ID] = true
	}
	for _, gid := range body.Groups {
		if !groupSet[gid] {
			writeErr(w, http.StatusBadRequest, "Unknown group: "+gid)
			return
		}
	}

	before := s.mat.BaselineConfig(name)
	after := rights.UserConfig{Groups: dedupe(body.Groups), Overrides: body.Overrides}

	// Authorize the group-assignment delta (admin only).
	if !sameSet(before.Groups, after.Groups) && !caller.IsAdmin {
		writeErr(w, http.StatusForbidden, "Only admins may change group membership")
		return
	}
	// Authorize each changed override by its service.
	for key := range changedOverrides(before.Overrides, after.Overrides) {
		svc, _, ok := s.cat.KeyService(key)
		if !ok {
			writeErr(w, http.StatusBadRequest, "Unknown right: "+key)
			return
		}
		if !s.canManageService(caller, svc) {
			writeErr(w, http.StatusForbidden, "You are not allowed to manage "+svc+" rights")
			return
		}
	}

	if err := s.rs.SetUser(name, after); err != nil {
		log.Printf("privleg: persist grants %s failed: %v", name, err)
		writeErr(w, http.StatusInternalServerError, "Failed to save rights")
		return
	}
	if err := s.mat.Materialize(name); err != nil {
		log.Printf("privleg: materialize %s failed: %v", name, err)
		writeErr(w, http.StatusInternalServerError, "Failed to apply rights change")
		return
	}
	writeJSON(w, http.StatusOK, s.grantsFor(name))
}

func (s *Server) setAdmin(w http.ResponseWriter, r *http.Request, caller *auth.User) {
	name := r.PathValue("username")
	if !userRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Invalid username")
		return
	}
	if !s.ul.IsManaged(name) {
		writeErr(w, http.StatusNotFound, "Unknown user")
		return
	}
	if name == caller.Username {
		writeErr(w, http.StatusBadRequest, "You cannot change your own admin status")
		return
	}
	var body struct {
		Admin bool `json:"admin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := store.SetAdmin(name, body.Admin); err != nil {
		log.Printf("privleg: set admin %s=%v failed: %v", name, body.Admin, err)
		writeErr(w, http.StatusInternalServerError, "Failed to change admin status")
		return
	}
	// Reconcile rights to the user's stored config now that their admin status changed.
	// Promotion is a no-op (admins are never materialized); demotion makes the user's own
	// stored config take effect immediately rather than waiting for their next edit.
	if err := s.mat.Materialize(name); err != nil {
		log.Printf("privleg: re-materialize %s after admin change: %v", name, err)
	}
	writeJSON(w, http.StatusOK, s.outFor(name))
}

// deleteUser deletes a holistic-managed account (admin-only, CSRF-guarded). It refuses to
// delete the caller's own account and only ever targets a managed user; the underlying root
// wrapper additionally refuses anything that is not a holistic user. ?purge=true also removes
// the user's home tree. The user's privleg rights config is dropped too.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, caller *auth.User) {
	name := r.PathValue("username")
	if !userRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Invalid username")
		return
	}
	if !s.ul.IsManaged(name) {
		writeErr(w, http.StatusNotFound, "Unknown user")
		return
	}
	if name == caller.Username {
		writeErr(w, http.StatusBadRequest, "You cannot delete your own account")
		return
	}
	// Never delete an admin account — admin status must be revoked first. Mirrors the
	// admin-target refusal in putGrants and the wrapper's own admin-group guard, so deletion
	// can't bypass the checks-and-balances the rest of privleg preserves.
	if s.ul.Resolve(name).IsAdmin {
		writeErr(w, http.StatusBadRequest, "Cannot delete an admin account — revoke admin status first")
		return
	}
	purge := r.URL.Query().Get("purge") == "true"
	// Drop the user's privleg rights config FIRST. It is reversible, so a failed cleanup aborts
	// BEFORE the irreversible OS deletion; and a later same-name account can never inherit stale
	// group assignments/overrides. (If the OS delete then fails, the account simply re-imports
	// its live rights on next edit — no resurrection, no orphaned config.)
	if err := s.rs.DeleteUser(name); err != nil {
		log.Printf("privleg: drop rights config for %s failed: %v", name, err)
		writeErr(w, http.StatusInternalServerError, "Failed to delete the account")
		return
	}
	if err := store.DeleteUser(name, purge); err != nil {
		log.Printf("privleg: delete user %s (purge=%v) failed: %v", name, purge, err)
		writeErr(w, http.StatusInternalServerError, "Failed to delete the account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) refresh(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	if err := s.cat.Reload(); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to reload rights catalog")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": len(s.cat.Manifests())})
}

// --- invites -------------------------------------------------------------
// Managing holistic registration invites is the `hp_priv_invite` right, which privleg
// declares like any other (admin-only to grant). Listing reads the store directly; minting
// and revoking delegate to the narrow root wrappers (see internal/invites).

// canInvite gates the invite endpoints: admins, or a non-admin holding hp_priv_invite.
func (s *Server) canInvite(u *auth.User) bool { return u.Can(inviteGroup) }

func (s *Server) listInvites(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	list, err := invites.List(time.Now().Unix())
	if err != nil {
		log.Printf("privleg: list invites failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "Could not read invites")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": list})
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var body struct {
		Note        string `json:"note"`
		ExpiresDays int    `json:"expiresDays"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if body.ExpiresDays < 0 || body.ExpiresDays > daysMax {
		writeErr(w, http.StatusBadRequest, "expiresDays must be between 0 and 3650")
		return
	}
	code, err := invites.New(body.ExpiresDays, sanitizeNote(body.Note))
	if err != nil {
		log.Printf("privleg: create invite failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "Could not create the invite")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code})
}

func (s *Server) revokeInvite(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id := r.PathValue("id")
	if !inviteIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "Invalid invite id")
		return
	}
	if err := invites.Revoke(id); err != nil {
		log.Printf("privleg: revoke invite %s failed: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "Could not revoke the invite")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sanitizeNote strips control characters and caps length, defence-in-depth before the value
// reaches the root wrapper (which re-sanitizes) and the shared invite store.
func sanitizeNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > noteMax {
		s = s[:noteMax]
	}
	return strings.TrimSpace(s)
}

// --- rights groups -------------------------------------------------------
// Admin-defined bundles of declared rights. Defining/changing them is admin-only; a change
// to a group's rights re-materializes every user assigned to it.

type groupOut struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Rights []string `json:"rights"`
}

func (s *Server) listGroups(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	gs := s.rs.ListGroups()
	out := make([]groupOut, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupOut{g.ID, g.Label, g.Rights})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

// validateGroupBody parses + validates the shared create/update body: a non-empty label and
// rights keys that are all currently declared (deduped, sorted).
func (s *Server) validateGroupBody(w http.ResponseWriter, r *http.Request) (string, []string, bool) {
	var body struct {
		Label  string   `json:"label"`
		Rights []string `json:"rights"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request body")
		return "", nil, false
	}
	label := sanitizeLabel(body.Label)
	if label == "" {
		writeErr(w, http.StatusBadRequest, "A group name is required")
		return "", nil, false
	}
	set := s.materializableSet()
	seen := map[string]bool{}
	keys := []string{}
	for _, k := range body.Rights {
		if !set[k] {
			writeErr(w, http.StatusBadRequest, "Unknown right: "+k)
			return "", nil, false
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return label, keys, true
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	label, keys, ok := s.validateGroupBody(w, r)
	if !ok {
		return
	}
	g, err := s.rs.CreateGroup(label, keys)
	if err != nil {
		log.Printf("privleg: create group failed: %v", err)
		writeErr(w, http.StatusInternalServerError, "Failed to create the group")
		return
	}
	writeJSON(w, http.StatusOK, groupOut{g.ID, g.Label, g.Rights})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id := r.PathValue("id")
	if !groupIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "Invalid group id")
		return
	}
	label, keys, ok := s.validateGroupBody(w, r)
	if !ok {
		return
	}
	g, affected, err := s.rs.UpdateGroup(id, label, keys)
	if errors.Is(err, rights.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "Unknown group")
		return
	} else if err != nil {
		log.Printf("privleg: update group %s failed: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "Failed to update the group")
		return
	}
	// Re-sync everyone in the group; best-effort (a per-user failure is logged, not fatal —
	// the saved definition is the source of truth and the next edit reconciles).
	if err := s.mat.MaterializeAll(affected); err != nil {
		log.Printf("privleg: re-materialize after group %s update: %v", id, err)
	}
	writeJSON(w, http.StatusOK, groupOut{g.ID, g.Label, g.Rights})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id := r.PathValue("id")
	if !groupIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "Invalid group id")
		return
	}
	affected, err := s.rs.DeleteGroup(id)
	if errors.Is(err, rights.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "Unknown group")
		return
	} else if err != nil {
		log.Printf("privleg: delete group %s failed: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "Failed to delete the group")
		return
	}
	if err := s.mat.MaterializeAll(affected); err != nil {
		log.Printf("privleg: re-materialize after group %s delete: %v", id, err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- helpers -------------------------------------------------------------

// trueKeys returns the sorted keys of a set that map to true.
func trueKeys(m map[string]bool) []string {
	out := []string{}
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// dedupe returns xs with duplicates removed, order-independent (sorted).
func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// sameSet reports whether two string slices contain the same elements (ignoring order/dupes).
func sameSet(a, b []string) bool {
	am, bm := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		am[x] = true
	}
	for _, x := range b {
		bm[x] = true
	}
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if !bm[k] {
			return false
		}
	}
	return true
}

// changedOverrides returns the set of right keys whose override value differs between before
// and after (added, removed, or flipped).
func changedOverrides(before, after map[string]string) map[string]bool {
	out := map[string]bool{}
	for k, v := range before {
		if after[k] != v {
			out[k] = true
		}
	}
	for k, v := range after {
		if before[k] != v {
			out[k] = true
		}
	}
	return out
}

// sanitizeLabel strips control characters, collapses surrounding whitespace and caps length.
func sanitizeLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > labelMax {
		s = strings.TrimSpace(s[:labelMax])
	}
	return s
}

func filterDeclared(groups []string, declared map[string]bool) []string {
	out := []string{}
	for _, g := range groups {
		if declared[g] {
			out = append(out, g)
		}
	}
	sort.Strings(out)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}
