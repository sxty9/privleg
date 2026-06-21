package rights

// The resolver is pure (no I/O), so the on/off/inherit precedence is trivially testable and
// shared by the materializer (write side) and the API grants view (display side).

// InheritedRights returns the rights granted purely by the union of a user's assigned
// groups, ignoring per-right overrides, restricted to currently-materializable keys. This
// is what the "Gruppe" state of the three-way switch resolves to (the UI labels the middle
// segment "Gruppe·an" / "Gruppe·aus" from it).
func InheritedRights(cfg UserConfig, groups []Group, materializable map[string]bool) map[string]bool {
	byID := make(map[string]Group, len(groups))
	for _, g := range groups {
		byID[g.ID] = g
	}
	out := map[string]bool{}
	for _, gid := range cfg.Groups {
		g, ok := byID[gid]
		if !ok {
			continue
		}
		for _, key := range g.Rights {
			if materializable[key] {
				out[key] = true
			}
		}
	}
	return out
}

// Effective resolves a user's effective right set over all materializable keys, applying the
// three-way precedence: an explicit override wins ("on" → granted, "off" → denied), else the
// right is granted iff at least one assigned group includes it. Keys not in `materializable`
// (e.g. a right whose backing group is no longer declared) are excluded — they can't be
// synced down, so they never appear in the diff.
func Effective(cfg UserConfig, groups []Group, materializable map[string]bool) map[string]bool {
	inherited := InheritedRights(cfg, groups, materializable)
	out := make(map[string]bool, len(materializable))
	for key := range materializable {
		switch cfg.Overrides[key] {
		case "on":
			out[key] = true
		case "off":
			out[key] = false
		default:
			out[key] = inherited[key]
		}
	}
	return out
}
