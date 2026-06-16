import {
  Badge,
  Button,
  Panel,
  Spinner,
  Stack,
  Switch,
  Text,
  useLiveQuery,
  useT,
  type ServiceContextProps,
} from '@holistic/ui';
import type { CatalogResponse, GrantsResponse } from './types';

interface Props extends ServiceContextProps {
  username: string;
  onBack: () => void;
}

export function RightsTab({ api, ui, user, username, onBack }: Props) {
  const t = useT();
  const cat = useLiveQuery<CatalogResponse>(() => api.get<CatalogResponse>('catalog'), 30000);
  const grants = useLiveQuery<GrantsResponse>(() => api.get<GrantsResponse>(`users/${username}/grants`), 5000);

  const services = cat.data?.services ?? [];
  const target = grants.data;

  if (!target) {
    return grants.loading ? <Spinner /> : <Text color="danger">{t('privleg.loadRightsError')}</Text>;
  }

  const held = new Set(target.rights);

  // May the calling user manage rights of this service for others? Admins always; a
  // delegated manager only for its service; privleg's own meta-rights are admin-only.
  function canManage(service: string): boolean {
    if (user.isAdmin) return true;
    if (service === 'privleg') return false;
    return user.groups.includes(`hp_priv_dlg_${service}`);
  }

  const toggle = async (group: string, label: string, dangerous: boolean, next: boolean) => {
    if (dangerous && next) {
      const ok = await ui.confirm({
        title: t('privleg.grantTitle', { label }),
        description: t('privleg.grantDesc'),
        confirmLabel: t('privleg.grant'),
      });
      if (!ok) return;
    }
    const nextRights = next ? [...target.rights, group] : target.rights.filter((g) => g !== group);
    try {
      await api.put(`users/${username}/grants`, { rights: nextRights });
      ui.toast({ title: t('privleg.rightsUpdated'), variant: 'success' });
      grants.refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.saveFailed'), description: (e as Error).message, variant: 'error' });
    }
  };

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

      {services.length === 0 && <Text color="secondary">{t('privleg.noServiceRights')}</Text>}

      {services.flatMap((svc) =>
        svc.categories.map((c) => (
          <Panel key={`${svc.service}:${c.id}`} title={`${c.label} · ${svc.service}`} className="p-4">
            <Stack gap={3}>
              {c.description && (
                <Text variant="footnote" color="secondary">
                  {c.description}
                </Text>
              )}
              {c.permissions.map((p) => {
                // A right's storage key: a backing group for normal rights, or the
                // fully-qualified id "svc:cat:id" for a shell permission (no group — the
                // user's login shell is the single source of truth, toggled by the backend).
                const key = p.type === 'shell' ? `${svc.service}:${c.id}:${p.id}` : (p.group ?? '');
                const on = target.isAdmin || held.has(key);
                const disabled = target.isAdmin || !canManage(svc.service);
                return (
                  <Stack key={key} direction="row" align="center" justify="between" gap={3}>
                    <Stack gap={1}>
                      <Stack direction="row" align="center" gap={2}>
                        <Text weight="semibold">{p.label}</Text>
                        {p.dangerous && <Badge variant="warning">{t('privleg.badgeDangerous')}</Badge>}
                        {/* orange (the `net` token), distinct from the dangerous badge's amber `warning` */}
                        {p.sensitive && <Badge className="bg-net/15 text-net">{t('privleg.badgeSensitive')}</Badge>}
                        {p.default && <Badge variant="neutral">{t('privleg.badgeDefaultOn')}</Badge>}
                      </Stack>
                      {p.description && (
                        <Text variant="footnote" color="secondary">
                          {p.description}
                        </Text>
                      )}
                    </Stack>
                    <Switch checked={on} disabled={disabled} onChange={(next) => toggle(key, p.label, !!p.dangerous, next)} />
                  </Stack>
                );
              })}
            </Stack>
          </Panel>
        )),
      )}
    </Stack>
  );
}
