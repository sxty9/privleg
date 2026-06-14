import {
  Badge,
  Button,
  Panel,
  Spinner,
  Stack,
  Switch,
  Text,
  useLiveQuery,
  type ServiceContextProps,
} from '@holistic/ui';
import type { CatalogResponse, GrantsResponse } from './types';

interface Props extends ServiceContextProps {
  username: string;
  onBack: () => void;
}

export function RightsTab({ api, ui, user, username, onBack }: Props) {
  const cat = useLiveQuery<CatalogResponse>(() => api.get<CatalogResponse>('catalog'), 30000);
  const grants = useLiveQuery<GrantsResponse>(() => api.get<GrantsResponse>(`users/${username}/grants`), 5000);

  const services = cat.data?.services ?? [];
  const target = grants.data;

  if (!target) {
    return grants.loading ? <Spinner /> : <Text color="danger">Konnte die Rechte nicht laden.</Text>;
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
        title: `„${label}" gewähren?`,
        description: 'Dieses Recht erlaubt eine potenziell weitreichende Aktion.',
        confirmLabel: 'Gewähren',
      });
      if (!ok) return;
    }
    const nextRights = next ? [...target.rights, group] : target.rights.filter((g) => g !== group);
    try {
      await api.put(`users/${username}/grants`, { rights: nextRights });
      ui.toast({ title: 'Rechte aktualisiert', variant: 'success' });
      grants.refresh();
    } catch (e) {
      ui.toast({ title: 'Konnte nicht speichern', description: (e as Error).message, variant: 'error' });
    }
  };

  return (
    <Stack gap={4}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Stack direction="row" align="center" gap={3}>
          <Button variant="ghost" size="sm" onClick={onBack}>
            ← Zurück
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
        {target.isAdmin && <Badge variant="accent">Admin — voller Zugriff</Badge>}
      </Stack>

      {target.isAdmin && (
        <Text variant="footnote" color="secondary">
          Admins haben uneingeschränkten Zugriff. Feingranulare Rechte gelten nur für Nicht-Admins — entziehe den
          Admin-Status, um sie einzeln zu steuern.
        </Text>
      )}

      {services.length === 0 && <Text color="secondary">Kein Dienst deklariert Rechte.</Text>}

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
                const on = target.isAdmin || held.has(p.group);
                const disabled = target.isAdmin || !canManage(svc.service);
                return (
                  <Stack key={p.group} direction="row" align="center" justify="between" gap={3}>
                    <Stack gap={1}>
                      <Stack direction="row" align="center" gap={2}>
                        <Text weight="semibold">{p.label}</Text>
                        {p.dangerous && <Badge variant="warning">heikel</Badge>}
                        {p.default && <Badge variant="neutral">Standard: an</Badge>}
                      </Stack>
                      {p.description && (
                        <Text variant="footnote" color="secondary">
                          {p.description}
                        </Text>
                      )}
                    </Stack>
                    <Switch checked={on} disabled={disabled} onChange={(next) => toggle(p.group, p.label, !!p.dangerous, next)} />
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
