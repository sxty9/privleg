import { useState } from 'react';
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  SearchField,
  Stack,
  Switch,
  Text,
  useLiveQuery,
  type Column,
  type ServiceContextProps,
} from '@holistic/ui';
import type { PrivlegUser, UsersResponse } from './types';

interface Props extends ServiceContextProps {
  onEdit: (username: string) => void;
}

export function UsersTab({ api, ui, user, onEdit }: Props) {
  const { data, refresh } = useLiveQuery<UsersResponse>(() => api.get<UsersResponse>('users'), 5000);
  const [q, setQ] = useState('');

  const all = data?.users ?? [];
  const needle = q.trim().toLowerCase();
  const rows = needle
    ? all.filter((u) => u.username.toLowerCase().includes(needle) || u.displayName.toLowerCase().includes(needle))
    : all;

  // Admin status is admin-only, and the backend forbids changing your own — mirror that here.
  const canToggleAdmin = (u: PrivlegUser) => user.isAdmin && u.username !== user.username;

  async function toggleAdmin(target: PrivlegUser, next: boolean) {
    const ok = await ui.confirm({
      title: next ? `${target.displayName} zum Admin machen?` : `Admin-Rechte von ${target.displayName} entziehen?`,
      description: next
        ? 'Admins haben uneingeschränkten Zugriff auf alle Dienste und können Rechte verwalten.'
        : 'Der Benutzer verliert den uneingeschränkten Zugriff. Feingranulare Rechte bleiben erhalten.',
      danger: !next,
      confirmLabel: next ? 'Zum Admin machen' : 'Entziehen',
    });
    if (!ok) return;
    try {
      await api.put(`users/${target.username}/admin`, { admin: next });
      ui.toast({ title: 'Aktualisiert', variant: 'success' });
      refresh();
    } catch (e) {
      ui.toast({ title: 'Konnte nicht ändern', description: (e as Error).message, variant: 'error' });
    }
  }

  const columns: Column<PrivlegUser>[] = [
    {
      key: 'displayName',
      header: 'Benutzer',
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
      header: 'Admin',
      align: 'right',
      width: 96,
      render: (u) => <Switch checked={u.isAdmin} disabled={!canToggleAdmin(u)} onChange={(next) => toggleAdmin(u, next)} />,
    },
    {
      key: 'rights',
      header: 'Rechte',
      align: 'right',
      width: 110,
      sortable: true,
      sortValue: (u) => (u.isAdmin ? Number.MAX_SAFE_INTEGER : u.rights.length),
      render: (u) => (u.isAdmin ? <Badge variant="accent">alle</Badge> : <Badge variant="neutral">{String(u.rights.length)}</Badge>),
    },
    {
      key: 'edit',
      header: '',
      align: 'right',
      width: 168,
      render: (u) => (
        <Button variant="secondary" size="sm" disabled={u.isAdmin} onClick={() => onEdit(u.username)}>
          Rechte bearbeiten
        </Button>
      ),
    },
  ];

  return (
    <Stack gap={3}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Text variant="subhead" weight="semibold">
          {String(rows.length)} Benutzer
        </Text>
        <SearchField value={q} onChange={setQ} placeholder="Nach Name oder Benutzer filtern" />
      </Stack>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(u) => u.username}
        initialSort={{ key: 'displayName', dir: 'asc' }}
        maxHeight={560}
        emptyState={<EmptyState title="Keine Benutzer" description="Es wurden keine holistic-Benutzer gefunden." />}
      />
    </Stack>
  );
}
