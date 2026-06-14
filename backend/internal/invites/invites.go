// Package invites surfaces holistic registration invites to privleg's management plane.
// It follows privleg's "daemon reads, wrappers write" rule: listing reads the invite store
// (/var/lib/holistic/invites.json) directly — privlegd runs in group `holistic`, which the
// store is group-readable by — while minting and revoking go through two narrow root
// wrappers that delegate to holistic-invites.py, the single source of truth for the store.
// The plaintext code is never stored and is returned by New() exactly once.
package invites

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	newWrapper    = "/usr/local/sbin/privleg-invite-new"
	revokeWrapper = "/usr/local/sbin/privleg-invite-revoke"
	defaultStore  = "/var/lib/holistic/invites.json"
)

func storePath() string {
	if p := os.Getenv("HOLISTIC_INVITES"); p != "" {
		return p
	}
	return defaultStore
}

// Invite is the API view of one invite. The plaintext code is never included.
type Invite struct {
	ID      string `json:"id"`
	Note    string `json:"note"`
	Created int64  `json:"created"`
	Expires *int64 `json:"expires"`
	UsedBy  string `json:"usedBy"`
	UsedAt  *int64 `json:"usedAt"`
	State   string `json:"state"` // active | used | revoked | expired
}

// rawInvite mirrors the on-disk shape written by holistic-invites.py.
type rawInvite struct {
	ID      string  `json:"id"`
	Note    string  `json:"note"`
	Created int64   `json:"created"`
	Expires *int64  `json:"expires"`
	UsedBy  *string `json:"used_by"`
	UsedAt  *int64  `json:"used_at"`
	Revoked bool    `json:"revoked"`
}

type rawStore struct {
	Invites []rawInvite `json:"invites"`
}

// stateOf mirrors the dashboard backend's precedence: used → revoked → expired → active.
func stateOf(r rawInvite, now int64) string {
	switch {
	case r.UsedBy != nil && *r.UsedBy != "":
		return "used"
	case r.Revoked:
		return "revoked"
	case r.Expires != nil && now > *r.Expires:
		return "expired"
	default:
		return "active"
	}
}

// List reads the invite store directly and computes each invite's state. A missing store
// (no invite ever minted) is not an error — it means "no invites".
func List(now int64) ([]Invite, error) {
	b, err := os.ReadFile(storePath())
	if err != nil {
		if os.IsNotExist(err) {
			return []Invite{}, nil
		}
		return nil, err
	}
	var s rawStore
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(s.Invites))
	for _, r := range s.Invites {
		usedBy := ""
		if r.UsedBy != nil {
			usedBy = *r.UsedBy
		}
		out = append(out, Invite{
			ID:      r.ID,
			Note:    r.Note,
			Created: r.Created,
			Expires: r.Expires,
			UsedBy:  usedBy,
			UsedAt:  r.UsedAt,
			State:   stateOf(r, now),
		})
	}
	return out, nil
}

// New mints a code via the root wrapper and returns the plaintext (shown once). The wrapper
// re-validates its inputs; expiresDays==0 means the code never expires.
func New(expiresDays int, note string) (string, error) {
	out, err := runOut(newWrapper, strconv.Itoa(expiresDays), note)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Revoke soft-revokes an invite by id via the root wrapper.
func Revoke(id string) error {
	_, err := runOut(revokeWrapper, id)
	return err
}

// runOut invokes a root wrapper via `sudo -n` and returns its stdout. Stderr is folded into
// the error so a failing wrapper surfaces its own message, mirroring store.run().
func runOut(wrapper string, args ...string) (string, error) {
	cmd := exec.Command("sudo", append([]string{"-n", wrapper}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s: %s", wrapper, msg)
	}
	return string(out), nil
}
