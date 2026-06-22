import { Badge, Button, Spinner, Stack, Text, useLiveQuery, useT, type ServiceContextProps } from '@holistic/ui';
import { RightsConfigEditor, type RightsConfigValue } from './RightsConfigEditor';
import type { CatalogResponse, GrantsResponse, GroupsResponse } from './types';

interface Props extends ServiceContextProps {
  username: string;
  onBack: () => void;
}

export function RightsTab({ api, ui, user, username, onBack }: Props) {
  const t = useT();
  const cat = useLiveQuery<CatalogResponse>(() => api.get<CatalogResponse>('catalog'), 30000);
  const grps = useLiveQuery<GroupsResponse>(() => api.get<GroupsResponse>('groups'), 30000);
  const grants = useLiveQuery<GrantsResponse>(() => api.get<GrantsResponse>(`users/${username}/grants`), 5000);

  const services = cat.data?.services ?? [];
  const groups = grps.data?.groups ?? [];
  const target = grants.data;

  if (!target) {
    return grants.loading ? <Spinner /> : <Text color="danger">{t('privleg.loadRightsError')}</Text>;
  }

  // May the calling user manage rights of this service for others? Admins always; a delegated
  // manager only for its service; privleg's own meta-rights are admin-only.
  function canManage(service: string): boolean {
    if (user.isAdmin) return true;
    if (service === 'privleg') return false;
    return user.groups.includes(`hp_priv_dlg_${service}`);
  }

  // Persist the full desired config (the backend diffs + authorizes each change).
  async function save(next: RightsConfigValue) {
    try {
      await api.put(`users/${username}/grants`, next);
      ui.toast({ title: t('privleg.rightsUpdated'), variant: 'success' });
      grants.refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.saveFailed'), description: (e as Error).message, variant: 'error' });
      grants.refresh(); // re-sync the UI to the server's actual state on failure
    }
  }

  return (
    <Stack gap={4}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Stack direction="row" align="center" gap={3}>
          <Button variant="ghost" size="sm" onClick={onBack}>
            {t('privleg.back')}
          </Button>
          <Stack gap={0}>
            <Text variant="subhead" weight="semibold">
              {target.displayName}
            </Text>
            <Text variant="footnote" color="secondary">
              {target.username}
            </Text>
          </Stack>
        </Stack>
        {target.isAdmin && <Badge variant="accent">{t('privleg.adminFullAccess')}</Badge>}
      </Stack>

      {target.isAdmin && (
        <Text variant="footnote" color="secondary">
          {t('privleg.adminNote')}
        </Text>
      )}

      <RightsConfigEditor
        services={services}
        groups={groups}
        value={{ groups: target.groups, overrides: target.overrides }}
        onChange={save}
        canManage={target.isAdmin ? () => false : canManage}
        assignmentEditable={user.isAdmin && !target.isAdmin}
        confirmDanger={(label) =>
          ui.confirm({ title: t('privleg.grantTitle', { label }), description: t('privleg.grantDesc'), confirmLabel: t('privleg.grant') })
        }
      />
    </Stack>
  );
}
