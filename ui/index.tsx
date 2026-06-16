import { UserIcon, type HolisticUser, type ServicePlugin } from '@holistic/ui';
import { Dashboard } from './Dashboard';
import './i18n';

// Visible to admins and to non-admins holding a privleg right: the view right, a delegated
// manager right (hp_priv_dlg_*), or the invite-management right (hp_priv_invite).
function canSeePrivleg(user: HolisticUser): boolean {
  return (
    user.isAdmin ||
    user.groups.some((g) => g === 'hp_priv_view' || g === 'hp_priv_invite' || g.startsWith('hp_priv_dlg_'))
  );
}

// privleg's dashboard plugin. Linked into holistic/frontend/external/privleg at install
// time and discovered by the host SPA's build-time registry. id MUST equal the link dir.
const plugin: ServicePlugin = {
  id: 'privleg',
  displayName: 'Permissions',
  icon: UserIcon,
  order: 5,
  visible: canSeePrivleg,
  Component: Dashboard,
};

export default plugin;
