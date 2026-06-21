// Package store applies rights changes by toggling Linux group membership through two
// narrow root wrappers. privleg never runs gpasswd directly: the wrappers enforce the
// hard boundaries (privleg-grant only touches declared hp_* groups; privleg-set-admin
// only touches the sudo group), so a bug here can never escalate beyond those.
package store

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	grantWrapper  = "/usr/local/sbin/privleg-grant"
	adminWrapper  = "/usr/local/sbin/privleg-set-admin"
	shellWrapper  = "/usr/local/sbin/privleg-set-shell"
	deleteWrapper = "/usr/local/sbin/privleg-delete-user"
)

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func run(wrapper string, args ...string) error {
	cmd := exec.Command("sudo", append([]string{"-n", wrapper}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s: %s", wrapper, msg)
	}
	return nil
}

// SetGrant adds (on) or removes (off) a user to/from a rights group. The wrapper rejects
// any group not declared in permissions.d, so an undeclared or protected group fails here.
func SetGrant(username, group string, on bool) error {
	return run(grantWrapper, username, group, onOff(on))
}

// SetAdmin adds (on) or removes (off) a user to/from the admin (sudo) group.
func SetAdmin(username string, on bool) error {
	return run(adminWrapper, username, onOff(on))
}

// SetShell toggles a user's login shell: on => a real login shell, off => nologin. The
// wrapper hardcodes the allowed shells and only ever touches holistic-managed users, so
// privleg never passes a shell path and can never set an arbitrary one. This is the write
// side of the "login shell is the single source of truth for shell access" model.
func SetShell(username string, on bool) error {
	return run(shellWrapper, username, onOff(on))
}

// DeleteUser removes a holistic-managed user's Samba + Linux account via the narrow root
// wrapper; purge also removes their home tree (userdel -r). The wrapper fails closed: it
// refuses any account that is not a member of the holistic users group AND any account in the
// admin group, so this can never delete a system, infrastructure, or admin account even if
// called with one.
func DeleteUser(username string, purge bool) error {
	if purge {
		return run(deleteWrapper, username, "--purge")
	}
	return run(deleteWrapper, username)
}
