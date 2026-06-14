package api

import (
	"testing"

	"privleg/internal/auth"
)

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
