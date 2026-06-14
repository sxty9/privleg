import { useState } from 'react';
import { ContentRegion, Stack, type ServiceContextProps } from '@holistic/ui';
import { UsersTab } from './UsersTab';
import { RightsTab } from './RightsTab';

// Master/detail: the user list, or the rights editor for one selected non-admin user.
export function Dashboard(props: ServiceContextProps) {
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <ContentRegion>
      <Stack gap={4}>
        {editing === null ? (
          <UsersTab {...props} onEdit={setEditing} />
        ) : (
          <RightsTab {...props} username={editing} onBack={() => setEditing(null)} />
        )}
      </Stack>
    </ContentRegion>
  );
}
