package api

import (
	"reflect"
	"testing"

	"privleg/internal/auth"
)

// sameSet and changedOverrides gate authorization in putGrants — a wrong answer here is an
// escalation (a non-admin slipping a group change through, or an override change going
// un-authorized), so they're tested directly.
func TestSameSet(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"g1"}, []string{"g1"}, true},
		{[]string{"g1", "g2"}, []string{"g2", "g1"}, true}, // order-independent
		{[]string{"g1", "g1"}, []string{"g1"}, true},       // dupe-independent
		{[]string{"g1"}, []string{"g1", "g2"}, false},      // added
		{[]string{"g1", "g2"}, []string{"g1"}, false},      // removed
		{[]string{"g1"}, []string{"g2"}, false},            // swapped
	}
	for _, c := range cases {
		if got := sameSet(c.a, c.b); got != c.want {
			t.Errorf("sameSet(%v,%v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestChangedOverrides(t *testing.T) {
	before := map[string]string{"hp_a": "on", "hp_b": "off"}
	after := map[string]string{"hp_a": "on", "hp_c": "on"} // hp_b removed, hp_c added, hp_a same
	got := changedOverrides(before, after)
	want := map[string]bool{"hp_b": true, "hp_c": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changedOverrides = %v, want %v", got, want)
	}
	// flip in place is a change
	got = changedOverrides(map[string]string{"hp_a": "on"}, map[string]string{"hp_a": "off"})
	if !got["hp_a"] {
		t.Error("a flipped override must be detected as changed")
	}
	if len(changedOverrides(before, before)) != 0 {
		t.Error("identical override maps must report no changes")
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := sanitizeLabel("  Eltern  "); got != "Eltern" {
		t.Errorf("trim = %q", got)
	}
	if got := sanitizeLabel("a\x00b\tc"); got != "ab c" {
		t.Errorf("control strip = %q, want %q", got, "ab c")
	}
	long := make([]byte, 100)
	for i := range long {
		long[i] = 'x'
	}
	if got := sanitizeLabel(string(long)); len(got) > 64 {
		t.Errorf("label not capped: len=%d", len(got))
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"b", "a", "b", "a"})
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("dedupe = %v, want [a b]", got)
	}
}

// canManageService is the core delegation rule: admins manage everything; a delegated
// manager manages only its own service; privleg's own meta-rights are admin-only.
func TestCanManageService(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name   string
		user   *auth.User
		svc    string
		expect bool
	}{
		{"admin manages hostek", &auth.User{IsAdmin: true}, "hostek", true},
		{"admin manages privleg meta", &auth.User{IsAdmin: true}, "privleg", true},
		{"delegate manages own service", &auth.User{Groups: []string{"hp_priv_dlg_hostek"}}, "hostek", true},
		{"delegate cannot manage other service", &auth.User{Groups: []string{"hp_priv_dlg_samba"}}, "hostek", false},
		{"delegate cannot manage privleg meta", &auth.User{Groups: []string{"hp_priv_dlg_privleg"}}, "privleg", false},
		{"plain user manages nothing", &auth.User{Groups: []string{"family", "smbusers"}}, "hostek", false},
		{"no delegate for privleg even with view", &auth.User{Groups: []string{"hp_priv_view"}}, "privleg", false},
	}
	for _, c := range cases {
		if got := s.canManageService(c.user, c.svc); got != c.expect {
			t.Errorf("%s: canManageService(%v, %q) = %v, want %v", c.name, c.user.Groups, c.svc, got, c.expect)
		}
	}
}

// isManager decides who may open the console (read users/catalog/grants).
func TestIsManager(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name   string
		user   *auth.User
		expect bool
	}{
		{"admin", &auth.User{IsAdmin: true}, true},
		{"viewer", &auth.User{Groups: []string{"hp_priv_view"}}, true},
		{"delegate", &auth.User{Groups: []string{"hp_priv_dlg_hostek"}}, true},
		{"plain user", &auth.User{Groups: []string{"family", "smbusers"}}, false},
		{"holds an unrelated right only", &auth.User{Groups: []string{"hp_hostek_power"}}, false},
	}
	for _, c := range cases {
		if got := s.isManager(c.user); got != c.expect {
			t.Errorf("%s: isManager(%v) = %v, want %v", c.name, c.user.Groups, got, c.expect)
		}
	}
}

// Can on auth.User: admins hold every right; others need the backing group.
func TestUserCan(t *testing.T) {
	admin := &auth.User{IsAdmin: true}
	if !admin.Can("hp_hostek_power") {
		t.Error("admin should hold every right")
	}
	user := &auth.User{Groups: []string{"hp_hostek_power"}}
	if !user.Can("hp_hostek_power") {
		t.Error("user in group should hold the right")
	}
	if user.Can("hp_hostek_proc") {
		t.Error("user not in group should not hold the right")
	}
}
