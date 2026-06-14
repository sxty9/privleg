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
