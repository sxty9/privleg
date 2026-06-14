# privleg

Manage **holistic user rights**, as a holistic service. privleg is the management plane
for the holistic *rights standard*: it lets admins (and delegated managers) see every
user, toggle a user admin/non-admin, and grant or revoke each service's fine-grained
rights — all backed by Linux group membership, the single source of truth.

```bash
sudo ./privleg setup          # build daemon, wire systemd + sudo + Caddy, link UI, rebuild SPA
sudo ./privleg status         # daemon / wrappers / route / plugin health
sudo ./privleg uninstall      # remove (rights groups + grants are left intact)
```

After setup, a **Rechte** tab appears in the holistic dashboard for admins and delegated
managers.

## How it works

privleg follows the same pattern as hostek: a single-file bash CLI generates all system
artifacts inline, an unprivileged Go daemon (`privlegd`) serves `/api/services/privleg/*`
behind the shared holistic JWT session, and a `@holistic/ui` plugin provides the UI.

- **Rights = Linux groups.** Every fine-grained right a service offers is declared in
  `/etc/holistic/permissions.d/<service>.json` and backed 1:1 by an `hp_*` Linux group.
  Granting a right = adding the user to that group; each service enforces it live with
  `isAdmin || group ∈ user.groups`. **privleg is not in the request path** of any other
  service — a host without privleg behaves exactly as before (empty groups ⇒ admin-only;
  `default:true` rights are pre-granted by provisioning and simply stay on).
- **Admin = the `sudo` group**, the single source of truth. Admins implicitly hold every
  right; only their `sudo` membership is toggled (never on your own account).
- **privlegd reads, the wrappers write.** The daemon enumerates users from the OS and
  reads the rights catalog from `permissions.d`. All membership changes go through two
  narrow root wrappers:
  - `privleg-grant <user> <hp_group> <on|off>` — refuses anything that isn't a **declared**
    `hp_*` group (verified via `holistic-perms is-declared`), and hard-refuses
    `sudo`/`family`/`smbusers`/etc. Fails closed.
  - `privleg-set-admin <user> <on|off>` — touches the admin group **only**.

## Delegation (privleg's self-declared rights)

privleg declares its own rights through the same standard (`permissions.d/privleg.json`),
so a **non-admin** can be made a *delegated manager*:

| Right | Group | Effect |
|---|---|---|
| hostek-Rechte verwalten | `hp_priv_dlg_hostek` | may set hostek rights for other users |
| samba-Rechte verwalten  | `hp_priv_dlg_samba`  | may set samba rights for other users |
| Benutzer ansehen        | `hp_priv_view`       | may view the user list + rights, read-only |

A delegated manager can never change admin status, never manage a service it has no
delegation for, and never grant privleg's own meta-rights — those stay admin-only.

## API (`/api/services/privleg/`)

| Method · path | Who | What |
|---|---|---|
| `GET users` | manager | list holistic users (+ admin + held rights) |
| `GET catalog` | manager | aggregated rights manifests from every service |
| `GET users/{u}/grants` | manager | one user's held rights |
| `PUT users/{u}/grants` | admin / service delegate | set a user's rights for the services you manage |
| `PUT users/{u}/admin` | admin only | toggle admin (not on yourself) |
| `POST refresh` | admin | re-read the rights catalog |

Errors use holistic's `{"detail": "..."}` contract.

## Layout

```
privleg                         single-file CLI (setup/lifecycle/wrappers source of truth)
backend/cmd/privlegd/main.go    daemon entry point (127.0.0.1:8772)
backend/internal/auth/          shared-JWT session validation (live Linux groups)
backend/internal/catalog/       reads permissions.d → manifests + group→service index
backend/internal/users/         enumerates smbusers members, resolves admin + rights
backend/internal/store/         applies changes via the two root wrappers
backend/internal/api/           routes, auth gates, delegation enforcement
ui/                             @holistic/ui plugin (Users + Rights editor)
```

## Requirements

A working holistic install (provides the shared JWT secret, the `holistic` group, Caddy,
and `holistic-perms`). privleg autodetects the holistic repo (sibling `../holistic`, …) or
set `HOLISTIC_REPO`.
