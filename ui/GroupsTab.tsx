import { useState } from 'react';
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  Field,
  Input,
  Panel,
  Spinner,
  Stack,
  Switch,
  Text,
  useLiveQuery,
  useT,
  type Column,
  type ServiceContextProps,
} from '@holistic/ui';
import { RightsCatalog, type CatalogRight } from './RightsCatalog';
import type { CatalogResponse, GroupsResponse, RightsGroup } from './types';

// Admin-only management of rights groups: list, create, edit and delete the named bundles of
// rights that users inherit by membership. The editor reuses the shared rights catalog (the
// same selection as the per-user editor) with a plain on/off switch per right.
export function GroupsTab({ api, ui }: ServiceContextProps) {
  const t = useT();
  const { data, loading, refresh } = useLiveQuery<GroupsResponse>(() => api.get<GroupsResponse>('groups'), 5000);
  const cat = useLiveQuery<CatalogResponse>(() => api.get<CatalogResponse>('catalog'), 30000);
  const groups = data?.groups ?? [];

  // null = list view; 'new' = create; a group = edit that group.
  const [editing, setEditing] = useState<RightsGroup | 'new' | null>(null);

  async function remove(g: RightsGroup) {
    const ok = await ui.confirm({
      title: t('privleg.deleteGroupTitle', { label: g.label }),
      description: t('privleg.deleteGroupDesc'),
      danger: true,
      confirmLabel: t('privleg.deleteGroup'),
    });
    if (!ok) return;
    try {
      await api.del(`groups/${g.id}`);
      ui.toast({ title: t('privleg.groupDeleted'), variant: 'success' });
      refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.saveFailed'), description: (e as Error).message, variant: 'error' });
    }
  }

  if (editing !== null) {
    return (
      <GroupEditor
        services={cat.data?.services ?? []}
        initial={editing === 'new' ? null : editing}
        onCancel={() => setEditing(null)}
        onSave={async (label, rights) => {
          try {
            if (editing === 'new') await api.post('groups', { label, rights });
            else await api.put(`groups/${editing.id}`, { label, rights });
            ui.toast({ title: t('privleg.groupSaved'), variant: 'success' });
            setEditing(null);
            refresh();
          } catch (e) {
            ui.toast({ title: t('privleg.saveFailed'), description: (e as Error).message, variant: 'error' });
          }
        }}
      />
    );
  }

  const columns: Column<RightsGroup>[] = [
    {
      key: 'label',
      header: t('privleg.colGroup'),
      sortable: true,
      sortValue: (g) => g.label.toLowerCase(),
      hideable: false,
      render: (g) => <Text weight="semibold">{g.label}</Text>,
    },
    {
      key: 'rights',
      header: t('privleg.colRights'),
      align: 'right',
      width: 110,
      sortable: true,
      sortValue: (g) => g.rights.length,
      render: (g) => <Badge variant="neutral">{String(g.rights.length)}</Badge>,
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: 200,
      render: (g) => (
        <Stack direction="row" gap={2} justify="end">
          <Button variant="secondary" size="sm" onClick={() => setEditing(g)}>
            {t('privleg.editGroup')}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => remove(g)}>
            {t('privleg.deleteGroup')}
          </Button>
        </Stack>
      ),
    },
  ];

  return (
    <Stack gap={3}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Text variant="subhead" weight="semibold">
          {t('privleg.groupCount', { count: groups.length })}
        </Text>
        <Button variant="primary" size="sm" onClick={() => setEditing('new')}>
          {t('privleg.newGroup')}
        </Button>
      </Stack>
      {loading && groups.length === 0 ? (
        <Spinner />
      ) : (
        <DataTable
          columns={columns}
          rows={groups}
          rowKey={(g) => g.id}
          initialSort={{ key: 'label', dir: 'asc' }}
          maxHeight={560}
          emptyState={<EmptyState title={t('privleg.noGroups')} description={t('privleg.noGroupsDesc')} />}
        />
      )}
    </Stack>
  );
}

interface EditorProps {
  services: CatalogResponse['services'];
  initial: RightsGroup | null;
  onCancel: () => void;
  onSave: (label: string, rights: string[]) => Promise<void>;
}

function GroupEditor({ services, initial, onCancel, onSave }: EditorProps) {
  const t = useT();
  const [label, setLabel] = useState(initial?.label ?? '');
  const [selected, setSelected] = useState<Set<string>>(new Set(initial?.rights ?? []));
  const [busy, setBusy] = useState(false);

  const toggle = (key: string, on: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  const control = (right: CatalogRight) => (
    <Switch checked={selected.has(right.key)} onChange={(on) => toggle(right.key, on)} />
  );

  async function submit() {
    setBusy(true);
    try {
      await onSave(label.trim(), [...selected]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack gap={4}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Button variant="ghost" size="sm" onClick={onCancel}>
          {t('privleg.back')}
        </Button>
        <Stack direction="row" gap={2}>
          <Button variant="secondary" size="sm" onClick={onCancel}>
            {t('privleg.cancel')}
          </Button>
          <Button variant="primary" size="sm" loading={busy} disabled={label.trim() === ''} onClick={submit}>
            {t('privleg.saveGroup')}
          </Button>
        </Stack>
      </Stack>

      <Panel title={initial ? t('privleg.editGroupTitle') : t('privleg.newGroupTitle')} className="p-4">
        <Field label={t('privleg.groupNameLabel')} hint={t('privleg.groupNameHint')} className="max-w-[360px]">
          <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={t('privleg.groupNamePlaceholder')} maxLength={64} />
        </Field>
      </Panel>

      <RightsCatalog services={services} control={control} emptyText={t('privleg.noServiceRights')} />
    </Stack>
  );
}
