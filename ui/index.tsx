import { UserIcon, type HolisticUser, type ServicePlugin } from '@holistic/ui';
import { Dashboard } from './Dashboard';

// Visible to admins and to delegated managers (anyone holding a privleg meta-right).
function canSeePrivleg(user: HolisticUser): boolean {
  return user.isAdmin || user.groups.some((g) => g === 'hp_priv_view' || g.startsWith('hp_priv_dlg_'));
}

// privleg's dashboard plugin. Linked into holistic/frontend/external/privleg at install
// time and discovered by the host SPA's build-time registry. id MUST equal the link dir.
const plugin: ServicePlugin = {
  id: 'privleg',
  displayName: 'Rechte',
  icon: UserIcon,
  order: 5,
  visible: canSeePrivleg,
  Component: Dashboard,
};

export default plugin;
