import { useState } from 'react';
import {
  Badge,
  Button,
  CodeBlock,
  DataTable,
  EmptyState,
  Field,
  Input,
  Modal,
  Panel,
  Spinner,
  Stack,
  Text,
  useLiveQuery,
  type Column,
  type ServiceContextProps,
} from '@holistic/ui';
import type { CreatedInvite, Invite, InvitesResponse, InviteState } from './types';

const STATE_LABEL: Record<InviteState, string> = {
  active: 'Aktiv',
  used: 'Eingelöst',
  revoked: 'Widerrufen',
  expired: 'Abgelaufen',
};
const STATE_VARIANT: Record<InviteState, 'success' | 'neutral' | 'danger' | 'warning'> = {
  active: 'success',
  used: 'neutral',
  revoked: 'danger',
  expired: 'warning',
};

function fmtDate(secs: number | null): string {
  if (!secs) return '—';
  return new Date(secs * 1000).toLocaleDateString();
}

// Full invite management for admins + holders of hp_priv_invite: mint a code, list all
// codes (incl. who redeemed them), and revoke active ones. The daemon enforces the same gate.
export function InvitesTab({ api, ui }: ServiceContextProps) {
  const { data, loading, refresh } = useLiveQuery<InvitesResponse>(() => api.get<InvitesResponse>('invites'), 5000);
  const invites = data?.invites ?? [];

  const [note, setNote] = useState('');
  const [days, setDays] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<string | null>(null);

  async function create() {
    setBusy(true);
    try {
      const expiresDays = days.trim() === '' ? 0 : Math.max(0, Math.min(3650, parseInt(days, 10) || 0));
      const res = await api.post<CreatedInvite>('invites', { note: note.trim(), expiresDays });
      setCreated(res.code);
      setNote('');
      setDays('');
      refresh();
    } catch (e) {
      ui.toast({ title: 'Konnte keinen Code erzeugen', description: (e as Error).message, variant: 'error' });
    } finally {
      setBusy(false);
    }
  }

  async function revoke(inv: Invite) {
    const ok = await ui.confirm({
      title: 'Einladungscode widerrufen?',
      description: inv.note
        ? `Die Einladung „${inv.note}" wird ungültig und kann nicht mehr eingelöst werden.`
        : 'Der Code wird ungültig und kann nicht mehr eingelöst werden.',
      danger: true,
      confirmLabel: 'Widerrufen',
    });
    if (!ok) return;
    try {
      await api.post<{ ok: boolean }>(`invites/${inv.id}/revoke`);
      ui.toast({ title: 'Widerrufen', variant: 'success' });
      refresh();
    } catch (e) {
      ui.toast({ title: 'Konnte nicht widerrufen', description: (e as Error).message, variant: 'error' });
    }
  }

  const columns: Column<Invite>[] = [
    {
      key: 'note',
      header: 'Notiz',
      sortable: true,
      sortValue: (i) => i.note.toLowerCase(),
      hideable: false,
      render: (i) => (
        <Stack gap={0}>
          <Text weight="semibold">{i.note || 'Ohne Notiz'}</Text>
          <Text variant="footnote" color="secondary">
            {i.id}
          </Text>
        </Stack>
      ),
    },
    {
      key: 'state',
      header: 'Status',
      width: 130,
      sortable: true,
      sortValue: (i) => i.state,
      render: (i) => <Badge variant={STATE_VARIANT[i.state]}>{STATE_LABEL[i.state]}</Badge>,
    },
    {
      key: 'usedBy',
      header: 'Eingelöst von',
      render: (i) => <Text color="secondary">{i.usedBy || '—'}</Text>,
    },
    {
      key: 'created',
      header: 'Erstellt',
      align: 'right',
      width: 120,
      sortable: true,
      sortValue: (i) => i.created,
      render: (i) => (
        <Text variant="footnote" color="secondary">
          {fmtDate(i.created)}
        </Text>
      ),
    },
    {
      key: 'expires',
      header: 'Läuft ab',
      align: 'right',
      width: 120,
      render: (i) => (
        <Text variant="footnote" color="secondary">
          {fmtDate(i.expires)}
        </Text>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: 130,
      render: (i) =>
        i.state === 'active' ? (
          <Button variant="secondary" size="sm" onClick={() => revoke(i)}>
            Widerrufen
          </Button>
        ) : null,
    },
  ];

  return (
    <Stack gap={4}>
      <Panel title="Neuen Einladungscode erzeugen" className="p-4">
        <Stack gap={3}>
          <Text variant="footnote" color="secondary">
            Mit einem Einladungscode kann sich eine neue Person ein Konto anlegen. Der Code wird nur einmal angezeigt.
          </Text>
          <Stack direction="row" gap={3} align="end" wrap>
            <Field label="Notiz (optional)" hint="Wofür oder für wen ist dieser Code?" className="flex-1 min-w-[200px]">
              <Input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="z. B. für Oma"
                maxLength={200}
              />
            </Field>
            <Field label="Gültig für (Tage)" hint="0 = unbegrenzt" className="w-[160px]">
              <Input
                value={days}
                onChange={(e) => setDays(e.target.value.replace(/[^0-9]/g, ''))}
                placeholder="0"
                inputMode="numeric"
              />
            </Field>
            <Button variant="primary" loading={busy} onClick={create}>
              Code erzeugen
            </Button>
          </Stack>
        </Stack>
      </Panel>

      {loading && invites.length === 0 ? (
        <Spinner />
      ) : (
        <DataTable
          columns={columns}
          rows={invites}
          rowKey={(i) => i.id}
          initialSort={{ key: 'created', dir: 'desc' }}
          maxHeight={560}
          emptyState={<EmptyState title="Keine Einladungen" description="Es wurden noch keine Einladungscodes erzeugt." />}
        />
      )}

      <Modal
        open={created !== null}
        onOpenChange={(o) => !o && setCreated(null)}
        title="Einladungscode erstellt"
        description="Gib diesen Code an die Person weiter. Er wird nur jetzt angezeigt — danach lässt er sich nicht mehr einsehen."
        size="sm"
        footer={
          <Button variant="primary" onClick={() => setCreated(null)}>
            Fertig
          </Button>
        }
      >
        <CodeBlock code={created ?? ''} />
      </Modal>
    </Stack>
  );
}
