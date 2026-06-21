import { useState } from 'react';
import { ContentRegion, SegmentedControl, Stack, useT, type SegmentedOption, type ServiceContextProps } from '@holistic/ui';
import { UsersTab } from './UsersTab';
import { RightsTab } from './RightsTab';
import { GroupsTab } from './GroupsTab';
import { InvitesTab } from './InvitesTab';

type Tab = 'users' | 'groups' | 'invites';

// Three sections, each gated by its own rights (mirrors the daemon):
//   • Users:   admins, hp_priv_view, or any hp_priv_dlg_* delegated manager
//   • Groups:  admins only (a rights group can bundle cross-service rights)
//   • Invites: admins or hp_priv_invite holders
// A user only ever sees the tabs they may use; the switcher hides when only one is available.
export function Dashboard(props: ServiceContextProps) {
  const { user } = props;
  const t = useT();
  const [editing, setEditing] = useState<string | null>(null);

  const canUsers = user.isAdmin || user.groups.some((g) => g === 'hp_priv_view' || g.startsWith('hp_priv_dlg_'));
  const canGroups = user.isAdmin;
  const canInvites = user.isAdmin || user.groups.includes('hp_priv_invite');

  const tabs: SegmentedOption<Tab>[] = [];
  if (canUsers) tabs.push({ value: 'users', label: t('privleg.tabUsers') });
  if (canGroups) tabs.push({ value: 'groups', label: t('privleg.tabGroups') });
  if (canInvites) tabs.push({ value: 'invites', label: t('privleg.tabInvites') });

  const [tab, setTab] = useState<Tab>(canUsers ? 'users' : canGroups ? 'groups' : 'invites');

  return (
    <ContentRegion>
      <Stack gap={4}>
        {tabs.length > 1 && editing === null && <SegmentedControl options={tabs} value={tab} onChange={setTab} />}
        {tab === 'users' && canUsers ? (
          editing === null ? (
            <UsersTab {...props} onEdit={setEditing} />
          ) : (
            <RightsTab {...props} username={editing} onBack={() => setEditing(null)} />
          )
        ) : tab === 'groups' && canGroups ? (
          <GroupsTab {...props} />
        ) : canInvites ? (
          <InvitesTab {...props} />
        ) : null}
      </Stack>
    </ContentRegion>
  );
}
