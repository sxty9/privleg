package rights

import (
	"reflect"
	"sort"
	"testing"
)

func keysOf(m map[string]bool, want bool) []string {
	var out []string
	for k, v := range m {
		if v == want {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func TestEffectivePrecedence(t *testing.T) {
	groups := []Group{
		{ID: "g1", Rights: []string{"hp_a", "hp_b"}},
		{ID: "g2", Rights: []string{"hp_b", "hp_c"}},
	}
	materializable := map[string]bool{"hp_a": true, "hp_b": true, "hp_c": true, "hp_d": true}

	cfg := UserConfig{
		Groups:    []string{"g1", "g2"},
		Overrides: map[string]string{"hp_a": "off", "hp_d": "on"},
	}
	eff := Effective(cfg, groups, materializable)

	// hp_a: inherited from g1 but force-off → denied.
	// hp_b, hp_c: inherited from groups, no override → granted.
	// hp_d: not in any group but force-on → granted.
	gotOn := keysOf(eff, true)
	wantOn := []string{"hp_b", "hp_c", "hp_d"}
	if !reflect.DeepEqual(gotOn, wantOn) {
		t.Errorf("granted = %v, want %v", gotOn, wantOn)
	}
	if eff["hp_a"] {
		t.Error("hp_a force-off must beat group inheritance")
	}
}

func TestEffectiveIgnoresUnmaterializable(t *testing.T) {
	groups := []Group{{ID: "g1", Rights: []string{"hp_a", "hp_gone"}}}
	materializable := map[string]bool{"hp_a": true} // hp_gone no longer declared
	cfg := UserConfig{Groups: []string{"g1"}, Overrides: map[string]string{"hp_gone": "on"}}

	eff := Effective(cfg, groups, materializable)
	if _, present := eff["hp_gone"]; present {
		t.Error("a right that is no longer declared must not appear in the effective set")
	}
	if !eff["hp_a"] {
		t.Error("hp_a should still be granted")
	}
}

func TestInheritedIgnoresOverrides(t *testing.T) {
	groups := []Group{{ID: "g1", Rights: []string{"hp_a"}}}
	materializable := map[string]bool{"hp_a": true, "hp_b": true}
	cfg := UserConfig{
		Groups:    []string{"g1"},
		Overrides: map[string]string{"hp_a": "off", "hp_b": "on"},
	}
	inh := InheritedRights(cfg, groups, materializable)
	if !inh["hp_a"] {
		t.Error("hp_a is inherited from g1 regardless of the off override")
	}
	if inh["hp_b"] {
		t.Error("hp_b is force-on, not inherited from any group")
	}
}

func TestInheritedUnknownGroupIDsIgnored(t *testing.T) {
	groups := []Group{{ID: "g1", Rights: []string{"hp_a"}}}
	materializable := map[string]bool{"hp_a": true}
	cfg := UserConfig{Groups: []string{"g1", "ghost"}}
	inh := InheritedRights(cfg, groups, materializable)
	if len(keysOf(inh, true)) != 1 || !inh["hp_a"] {
		t.Errorf("assignment to a non-existent group id must be ignored, got %v", keysOf(inh, true))
	}
}
