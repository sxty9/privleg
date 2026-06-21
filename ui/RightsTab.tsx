import {
  Badge,
  Box,
  Button,
  Checkbox,
  Panel,
  SegmentedControl,
  Spinner,
  Stack,
  Text,
  useLiveQuery,
  useT,
  type SegmentedOption,
  type ServiceContextProps,
} from '@holistic/ui';
import { RightsCatalog, type CatalogRight } from './RightsCatalog';
import type { CatalogResponse, GrantsResponse, GroupsResponse, OverrideState } from './types';

interface Props extends ServiceContextProps {
  username: string;
  onBack: () => void;
}

// The three states of a per-right switch: force-off, inherit-from-groups, force-on.
type TriState = 'off' | 'group' | 'on';

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

  const assigned = new Set(target.groups);
  const inherited = new Set(target.inherited);
  const overrides = target.overrides;

  // May the calling user manage rights of this service for others? Admins always; a
  // delegated manager only for its service; privleg's own meta-rights are admin-only.
  function canManage(service: string): boolean {
    if (user.isAdmin) return true;
    if (service === 'privleg') return false;
    return user.groups.includes(`hp_priv_dlg_${service}`);
  }

  // Persist the full desired config (the backend diffs + authorizes each change).
  async function save(nextGroups: string[], nextOverrides: Record<string, OverrideState>) {
    try {
      await api.put(`users/${username}/grants`, { groups: nextGroups, overrides: nextOverrides });
      ui.toast({ title: t('privleg.rightsUpdated'), variant: 'success' });
      grants.refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.saveFailed'), description: (e as Error).message, variant: 'error' });
      grants.refresh(); // re-sync the UI to the server's actual state on failure
    }
  }

  async function toggleGroup(id: string, next: boolean) {
    const nextGroups = next ? [...target!.groups, id] : target!.groups.filter((g) => g !== id);
    await save(nextGroups, overrides);
  }

  async function setTri(right: CatalogRight, next: TriState) {
    if (next === 'on' && right.perm.dangerous) {
      const ok = await ui.confirm({
        title: t('privleg.grantTitle', { label: right.label }),
        description: t('privleg.grantDesc'),
        confirmLabel: t('privleg.grant'),
      });
      if (!ok) return;
    }
    const nextOverrides: Record<string, OverrideState> = { ...overrides };
    if (next === 'group') delete nextOverrides[right.key];
    else nextOverrides[right.key] = next;
    await save(target!.groups, nextOverrides);
  }

  const triControl = (right: CatalogRight) => {
    const value: TriState = overrides[right.key] ?? 'group';
    const groupYields = inherited.has(right.key);
    const disabled = target!.isAdmin || !canManage(right.service);
    const options: SegmentedOption<TriState>[] = [
      { value: 'off', label: t('privleg.triOff') },
      { value: 'group', label: groupYields ? t('privleg.triGroupOn') : t('privleg.triGroupOff') },
      { value: 'on', label: t('privleg.triOn') },
    ];
    return (
      <Box className={disabled ? 'pointer-events-none opacity-50' : undefined}>
        <SegmentedControl options={options} value={value} onChange={(v) => setTri(right, v)} />
      </Box>
    );
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

      {/* Group assignment: admins pick the groups the user belongs to; delegated managers see
          the membership read-only (only admins may change it, mirroring the daemon). */}
      <Panel title={t('privleg.assignGroupsTitle')} className="p-4">
        <Stack gap={3}>
          <Text variant="footnote" color="secondary">
            {t('privleg.assignGroupsIntro')}
          </Text>
          {groups.length === 0 ? (
            <Text variant="footnote" color="secondary">
              {t('privleg.noGroupsYet')}
            </Text>
          ) : user.isAdmin && !target.isAdmin ? (
            <Stack gap={2}>
              {groups.map((g) => (
                <Checkbox key={g.id} checked={assigned.has(g.id)} onChange={(next) => toggleGroup(g.id, next)} label={g.label} />
              ))}
            </Stack>
          ) : (
            <Stack direction="row" gap={2} wrap>
              {target.groups.length === 0 ? (
                <Text variant="footnote" color="secondary">
                  {t('privleg.noGroupsAssigned')}
                </Text>
              ) : (
                groups.filter((g) => assigned.has(g.id)).map((g) => <Badge key={g.id} variant="neutral">{g.label}</Badge>)
              )}
            </Stack>
          )}
        </Stack>
      </Panel>

      <RightsCatalog services={services} control={triControl} emptyText={t('privleg.noServiceRights')} />
    </Stack>
  );
}
