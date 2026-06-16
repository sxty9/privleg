// Package catalog reads every service's rights manifest from the holistic drop-in
// directory (/etc/holistic/permissions.d/<service>.json) and indexes which service
// declares each backing group. It is privleg's view of "which rights exist"; it never
// changes membership (that is the store's job, gated by the wrappers).
package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultDir is the holistic rights drop-in directory.
const DefaultDir = "/etc/holistic/permissions.d"

// Perm mirrors PermissionDecl in @holistic/ui.
type Perm struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	// Type is "group" (default, backed by a Linux group) or "shell" (the user's login
	// shell — the single source of truth — toggled via usermod; no backing group).
	Type        string `json:"type,omitempty"`
	Group       string `json:"group,omitempty"`
	Shell       string `json:"shell,omitempty"` // login shell to set when a "shell" perm is granted
	Default     bool   `json:"default,omitempty"`
	Dangerous   bool   `json:"dangerous,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

// Category groups related rights within one service.
type Category struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Permissions []Perm `json:"permissions"`
}

// Manifest is one service's declared rights.
type Manifest struct {
	Service    string     `json:"service"`
	Version    int        `json:"version"`
	Categories []Category `json:"categories"`
}

// Catalog is a cached, reloadable view of all manifests.
type Catalog struct {
	dir          string
	mu           sync.RWMutex
	manifests    []Manifest
	groupService map[string]string // backing group -> declaring service
	shellService map[string]string // shell-perm key "svc:cat:id" -> declaring service
}

// New builds a catalog and loads it once.
func New(dir string) *Catalog {
	if dir == "" {
		dir = DefaultDir
	}
	c := &Catalog{dir: dir, groupService: map[string]string{}, shellService: map[string]string{}}
	_ = c.Reload()
	return c
}

// Reload re-reads the drop-in directory. A missing directory is treated as "no rights".
func (c *Catalog) Reload() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			c.swap(nil, map[string]string{}, map[string]string{})
			return nil
		}
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var ms []Manifest
	gs := map[string]string{}
	ss := map[string]string{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(c.dir, n))
		if err != nil {
			continue
		}
		var m Manifest
		if json.Unmarshal(b, &m) != nil || m.Service == "" {
			continue // skip malformed manifests, like the SPA registry skips bad plugins
		}
		ms = append(ms, m)
		for _, cat := range m.Categories {
			for _, p := range cat.Permissions {
				if p.Type == "shell" {
					ss[m.Service+":"+cat.ID+":"+p.ID] = m.Service
				} else if p.Group != "" {
					gs[p.Group] = m.Service
				}
			}
		}
	}
	c.swap(ms, gs, ss)
	return nil
}

func (c *Catalog) swap(ms []Manifest, gs, ss map[string]string) {
	c.mu.Lock()
	c.manifests, c.groupService, c.shellService = ms, gs, ss
	c.mu.Unlock()
}

// Manifests returns the current manifests (read-only snapshot).
func (c *Catalog) Manifests() []Manifest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.manifests
}

// ServiceOf returns the service that declares a backing group, and whether it is declared.
func (c *Catalog) ServiceOf(group string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.groupService[group]
	return s, ok
}

// IsDeclared reports whether the group backs a declared right.
func (c *Catalog) IsDeclared(group string) bool {
	_, ok := c.ServiceOf(group)
	return ok
}

// DeclaredSet returns the set of all backing groups.
func (c *Catalog) DeclaredSet() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]bool, len(c.groupService))
	for g := range c.groupService {
		out[g] = true
	}
	return out
}

// ShellPermSet returns the set of declared shell-permission keys ("svc:cat:id").
func (c *Catalog) ShellPermSet() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]bool, len(c.shellService))
	for k := range c.shellService {
		out[k] = true
	}
	return out
}

// ShellServiceOf returns the service that declares a shell-permission key, and whether
// the key is a declared shell permission.
func (c *Catalog) ShellServiceOf(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.shellService[key]
	return s, ok
}
