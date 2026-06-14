import { useState } from 'react';
import { ContentRegion, SegmentedControl, Stack, type SegmentedOption, type ServiceContextProps } from '@holistic/ui';
import { UsersTab } from './UsersTab';
import { RightsTab } from './RightsTab';
import { InvitesTab } from './InvitesTab';

type Tab = 'users' | 'invites';

// Two sections, each gated by its own rights (mirrors the daemon):
//   • Benutzer:    admins, hp_priv_view, or any hp_priv_dlg_* delegated manager
//   • Einladungen: admins or hp_priv_invite holders
// A user only ever sees the tabs they may use; the switcher hides when only one is available.
export function Dashboard(props: ServiceContextProps) {
  const { user } = props;
  const [editing, setEditing] = useState<string | null>(null);

  const canUsers = user.isAdmin || user.groups.some((g) => g === 'hp_priv_view' || g.startsWith('hp_priv_dlg_'));
  const canInvites = user.isAdmin || user.groups.includes('hp_priv_invite');

  const tabs: SegmentedOption<Tab>[] = [];
  if (canUsers) tabs.push({ value: 'users', label: 'Benutzer' });
  if (canInvites) tabs.push({ value: 'invites', label: 'Einladungen' });

  const [tab, setTab] = useState<Tab>(canUsers ? 'users' : 'invites');
  const showUsers = tab === 'users' && canUsers;

  return (
    <ContentRegion>
      <Stack gap={4}>
        {tabs.length > 1 && editing === null && <SegmentedControl options={tabs} value={tab} onChange={setTab} />}
        {showUsers ? (
          editing === null ? (
            <UsersTab {...props} onEdit={setEditing} />
          ) : (
            <RightsTab {...props} username={editing} onBack={() => setEditing(null)} />
          )
        ) : (
          <InvitesTab {...props} />
        )}
      </Stack>
    </ContentRegion>
  );
}
