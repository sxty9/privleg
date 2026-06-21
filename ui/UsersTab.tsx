import { useState } from 'react';
import {
  Badge,
  Button,
  Checkbox,
  DataTable,
  EmptyState,
  Modal,
  SearchField,
  Stack,
  Switch,
  Text,
  useLiveQuery,
  useT,
  type Column,
  type ServiceContextProps,
} from '@holistic/ui';
import type { PrivlegUser, UsersResponse } from './types';

interface Props extends ServiceContextProps {
  onEdit: (username: string) => void;
}

export function UsersTab({ api, ui, user, onEdit }: Props) {
  const t = useT();
  const { data, refresh } = useLiveQuery<UsersResponse>(() => api.get<UsersResponse>('users'), 5000);
  const [q, setQ] = useState('');
  const [del, setDel] = useState<PrivlegUser | null>(null);
  const [purge, setPurge] = useState(false);
  const [busy, setBusy] = useState(false);

  const all = data?.users ?? [];
  const needle = q.trim().toLowerCase();
  const rows = needle
    ? all.filter((u) => u.username.toLowerCase().includes(needle) || u.displayName.toLowerCase().includes(needle))
    : all;

  // Admin status is admin-only, and the backend forbids changing your own — mirror that here.
  const canToggleAdmin = (u: PrivlegUser) => user.isAdmin && u.username !== user.username;

  async function toggleAdmin(target: PrivlegUser, next: boolean) {
    const ok = await ui.confirm({
      title: next ? t('privleg.makeAdminTitle', { name: target.displayName }) : t('privleg.revokeAdminTitle', { name: target.displayName }),
      description: next ? t('privleg.makeAdminDesc') : t('privleg.revokeAdminDesc'),
      danger: !next,
      confirmLabel: next ? t('privleg.makeAdmin') : t('privleg.revokeAdmin'),
    });
    if (!ok) return;
    try {
      await api.put(`users/${target.username}/admin`, { admin: next });
      ui.toast({ title: t('privleg.updated'), variant: 'success' });
      refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.changeFailed'), description: (e as Error).message, variant: 'error' });
    }
  }

  // Account deletion is admin-only, never on yourself, and never on another admin (revoke
  // their admin status first). The backend + the root wrapper enforce all three.
  const canDelete = (u: PrivlegUser) => user.isAdmin && u.username !== user.username && !u.isAdmin;

  async function confirmDelete() {
    if (!del) return;
    setBusy(true);
    try {
      await api.del(`users/${del.username}${purge ? '?purge=true' : ''}`);
      ui.toast({ title: t('privleg.accountDeleted'), variant: 'success' });
      setDel(null);
      setPurge(false);
      refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.deleteFailed'), description: (e as Error).message, variant: 'error' });
    } finally {
      setBusy(false);
    }
  }

  const columns: Column<PrivlegUser>[] = [
    {
      key: 'displayName',
      header: t('privleg.colUser'),
      sortable: true,
      sortValue: (u) => u.displayName.toLowerCase(),
      hideable: false,
      render: (u) => (
        <Stack gap={0}>
          <Text weight="semibold">{u.displayName}</Text>
          <Text variant="footnote" color="secondary">
            {u.username}
          </Text>
        </Stack>
      ),
    },
    {
      key: 'admin',
      header: t('privleg.colAdmin'),
      align: 'right',
      width: 96,
      render: (u) => <Switch checked={u.isAdmin} disabled={!canToggleAdmin(u)} onChange={(next) => toggleAdmin(u, next)} />,
    },
    {
      key: 'rights',
      header: t('privleg.colRights'),
      align: 'right',
      width: 110,
      sortable: true,
      sortValue: (u) => (u.isAdmin ? Number.MAX_SAFE_INTEGER : u.rights.length),
      render: (u) => (u.isAdmin ? <Badge variant="accent">{t('privleg.rightsAll')}</Badge> : <Badge variant="neutral">{String(u.rights.length)}</Badge>),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: 260,
      render: (u) => (
        <Stack direction="row" gap={2} justify="end">
          <Button variant="secondary" size="sm" disabled={u.isAdmin} onClick={() => onEdit(u.username)}>
            {t('privleg.editRights')}
          </Button>
          {canDelete(u) && (
            <Button variant="ghost" size="sm" onClick={() => { setPurge(false); setDel(u); }}>
              {t('privleg.deleteAccount')}
            </Button>
          )}
        </Stack>
      ),
    },
  ];

  return (
    <Stack gap={3}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Text variant="subhead" weight="semibold">
          {t('privleg.userCount', { count: rows.length })}
        </Text>
        <SearchField value={q} onChange={setQ} placeholder={t('privleg.filterUsers')} />
      </Stack>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(u) => u.username}
        initialSort={{ key: 'displayName', dir: 'asc' }}
        maxHeight={560}
        emptyState={<EmptyState title={t('privleg.noUsers')} description={t('privleg.noUsersDesc')} />}
      />

      <Modal
        open={del !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDel(null);
            setPurge(false);
          }
        }}
        title={t('privleg.deleteAccountTitle', { name: del?.displayName ?? '' })}
        description={t('privleg.deleteAccountDesc')}
        size="sm"
        footer={
          <Stack direction="row" gap={2} justify="end">
            <Button variant="secondary" onClick={() => { setDel(null); setPurge(false); }}>
              {t('privleg.cancel')}
            </Button>
            <Button variant="destructive" loading={busy} onClick={confirmDelete}>
              {t('privleg.deleteAccount')}
            </Button>
          </Stack>
        }
      >
        <Stack gap={2}>
          <Checkbox checked={purge} onChange={setPurge} label={t('privleg.deleteAccountPurge')} />
          <Text variant="footnote" color="secondary">
            {t('privleg.deleteAccountPurgeHint')}
          </Text>
        </Stack>
      </Modal>
    </Stack>
  );
}
