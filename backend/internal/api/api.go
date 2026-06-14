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
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"privleg/internal/auth"
	"privleg/internal/catalog"
	"privleg/internal/invites"
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
)

// Server wires the verifier, catalog and user lister into HTTP handlers.
type Server struct {
	v   *auth.Verifier
	cat *catalog.Catalog
	ul  *users.Lister
}

// New builds a server.
func New(v *auth.Verifier, cat *catalog.Catalog, ul *users.Lister) *Server {
	return &Server{v: v, cat: cat, ul: ul}
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
	declared := s.cat.DeclaredSet()
	all := s.ul.List()
	out := make([]userOut, 0, len(all))
	for _, u := range all {
		out = append(out, userOut{u.Username, u.DisplayName, u.IsAdmin, filterDeclared(u.Groups, declared)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) getCatalog(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	// Re-read the drop-in directory so rights a service just installed or updated show up
	// live — without needing a privleg restart or a manual refresh. Best-effort: on a read
	// error the last-good catalog is kept.
	_ = s.cat.Reload()
	writeJSON(w, http.StatusOK, map[string]any{"services": s.cat.Manifests()})
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
	u := s.ul.Resolve(name)
	writeJSON(w, http.StatusOK, userOut{u.Username, u.DisplayName, u.IsAdmin, filterDeclared(u.Groups, s.cat.DeclaredSet())})
}

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
	var body struct {
		Rights []string `json:"rights"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Desired set: every requested group must be a declared right.
	desired := map[string]bool{}
	for _, g := range body.Rights {
		if !s.cat.IsDeclared(g) {
			writeErr(w, http.StatusBadRequest, "Unknown right: "+g)
			return
		}
		desired[g] = true
	}
	declared := s.cat.DeclaredSet()
	current := map[string]bool{}
	for _, g := range filterDeclared(s.ul.Resolve(name).Groups, declared) {
		current[g] = true
	}

	// Diff into add/remove changes.
	type change struct {
		group string
		on    bool
	}
	var changes []change
	for g := range desired {
		if !current[g] {
			changes = append(changes, change{g, true})
		}
	}
	for g := range current {
		if !desired[g] {
			changes = append(changes, change{g, false})
		}
	}

	// Authorize EVERY change before applying ANY (no partial escalation).
	for _, ch := range changes {
		svc, _ := s.cat.ServiceOf(ch.group)
		if !s.canManageService(caller, svc) {
			writeErr(w, http.StatusForbidden, "You are not allowed to manage "+svc+" rights")
			return
		}
	}
	// Apply.
	for _, ch := range changes {
		if err := store.SetGrant(name, ch.group, ch.on); err != nil {
			log.Printf("privleg: set grant %s %s=%v failed: %v", name, ch.group, ch.on, err)
			writeErr(w, http.StatusInternalServerError, "Failed to apply rights change")
			return
		}
	}
	u := s.ul.Resolve(name)
	writeJSON(w, http.StatusOK, userOut{u.Username, u.DisplayName, u.IsAdmin, filterDeclared(u.Groups, declared)})
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
	u := s.ul.Resolve(name)
	writeJSON(w, http.StatusOK, userOut{u.Username, u.DisplayName, u.IsAdmin, filterDeclared(u.Groups, s.cat.DeclaredSet())})
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

// --- helpers -------------------------------------------------------------

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
