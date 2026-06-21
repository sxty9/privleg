// JSON shapes returned by privlegd (/api/services/privleg/*). Field names mirror the
// Go backend's json tags. The rights manifest shape is the shared SDK type.
import type { PermissionManifest } from '@holistic/ui';

export interface PrivlegUser {
  username: string;
  displayName: string;
  isAdmin: boolean;
  rights: string[]; // declared rights groups the user currently holds
}

export interface UsersResponse {
  users: PrivlegUser[];
}

export interface CatalogResponse {
  services: PermissionManifest[];
}

// --- rights groups (GET/POST groups, PUT/DELETE groups/{id}) ---

// A rights group: an admin-defined bundle of declared rights. `rights` are catalog keys —
// a backing hp_* group, or a shell key "svc:cat:id" — the same identifiers the per-user
// editor uses. Membership in a group makes a user INHERIT every right it lists.
export interface RightsGroup {
  id: string;
  label: string;
  rights: string[];
}

export interface GroupsResponse {
  groups: RightsGroup[];
}

// A per-right manual override: force the right on or off, regardless of group inheritance.
// A right with no override is in the "group" (inherit) state.
export type OverrideState = 'on' | 'off';

// GET/PUT users/{u}/grants. `groups` are the assigned group ids; `overrides` are the manual
// deviations; `inherited` are the rights the assigned groups grant (ignoring overrides — the
// UI labels the "Gruppe" segment from it); `effective` is the fully resolved set enforced.
export interface GrantsResponse {
  username: string;
  displayName: string;
  isAdmin: boolean;
  groups: string[];
  overrides: Record<string, OverrideState>;
  inherited: string[];
  effective: string[];
}

// --- invites (GET/POST invites, POST invites/{id}/revoke) ---
export type InviteState = 'active' | 'used' | 'revoked' | 'expired';

export interface Invite {
  id: string;
  note: string;
  created: number; // unix seconds
  expires: number | null; // unix seconds, null = never
  usedBy: string; // "" until consumed
  usedAt: number | null;
  state: InviteState;
}

export interface InvitesResponse {
  invites: Invite[];
}

// POST invites returns the plaintext code exactly once.
export interface CreatedInvite {
  code: string;
}
