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

// GET/PUT users/{u}/grants return the same per-user shape.
export type GrantsResponse = PrivlegUser;

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
