// Package users enumerates holistic-managed users (members of the smbusers group, the
// same set the dashboard admin API lists) and resolves each one's groups + admin status
// live from the OS — Linux stays the single source of truth.
package users

import (
	"os/exec"
	"os/user"
	"sort"
	"strings"
)

// User is a holistic-managed account as seen by privleg.
type User struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	IsAdmin     bool     `json:"isAdmin"`
	Groups      []string `json:"groups"`
}

// Lister enumerates and resolves managed users.
type Lister struct {
	enumGroup  string // membership defines "a holistic user" (smbusers)
	adminGroup string // membership confers admin (sudo)
}

// NewLister builds a lister. enumGroup defaults to "smbusers", adminGroup to "sudo".
func NewLister(enumGroup, adminGroup string) *Lister {
	if enumGroup == "" {
		enumGroup = "smbusers"
	}
	if adminGroup == "" {
		adminGroup = "sudo"
	}
	return &Lister{enumGroup: enumGroup, adminGroup: adminGroup}
}

// Members returns the sorted usernames of holistic-managed accounts.
func (l *Lister) Members() []string {
	out, err := exec.Command("getent", "group", l.enumGroup).Output()
	if err != nil {
		return nil // group missing => no managed users
	}
	// getent group line: name:passwd:gid:member1,member2,...
	fields := strings.SplitN(strings.TrimSpace(string(out)), ":", 4)
	if len(fields) < 4 || fields[3] == "" {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, m := range strings.Split(fields[3], ",") {
		m = strings.TrimSpace(m)
		if m != "" && !seen[m] {
			seen[m] = true
			names = append(names, m)
		}
	}
	sort.Strings(names)
	return names
}

// IsManaged reports whether username is a holistic-managed account.
func (l *Lister) IsManaged(username string) bool {
	for _, m := range l.Members() {
		if m == username {
			return true
		}
	}
	return false
}

// List resolves every managed user.
func (l *Lister) List() []User {
	names := l.Members()
	out := make([]User, 0, len(names))
	for _, n := range names {
		out = append(out, l.Resolve(n))
	}
	return out
}

// Resolve reads one user's display name, groups and admin status live from the OS.
func (l *Lister) Resolve(username string) User {
	groups := resolveGroups(username)
	display := username
	if u, err := user.Lookup(username); err == nil {
		if name := strings.SplitN(u.Name, ",", 2)[0]; strings.TrimSpace(name) != "" {
			display = strings.TrimSpace(name)
		}
	}
	return User{
		Username:    username,
		DisplayName: display,
		IsAdmin:     contains(groups, l.adminGroup),
		Groups:      groups,
	}
}

func resolveGroups(username string) []string {
	if out, err := exec.Command("id", "-nG", username).Output(); err == nil {
		return strings.Fields(string(out))
	}
	return nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
