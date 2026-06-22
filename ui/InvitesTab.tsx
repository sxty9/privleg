import { useEffect, useRef, useState } from 'react';
import {
  Badge,
  Button,
  Checkbox,
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
  useT,
  type Column,
  type PermissionManifest,
  type ServiceContextProps,
} from '@holistic/ui';
import { RightsConfigEditor, type RightsConfigValue } from './RightsConfigEditor';
import { rightKey } from './RightsCatalog';
import type { CatalogResponse, CreatedInvite, GroupsResponse, Invite, InvitesResponse, InviteState } from './types';

const STATE_KEY: Record<InviteState, string> = {
  active: 'privleg.stateActive',
  used: 'privleg.stateUsed',
  revoked: 'privleg.stateRevoked',
  expired: 'privleg.stateExpired',
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

// Pre-seed an invite's rights config with the current default-on rights set to "on", so the
// template starts as a "default user" (parity with how an existing user's defaults show) and
// the admin adjusts from there. Mirrors the catalog's `default` flag.
function defaultSeed(services: PermissionManifest[]): Record<string, 'on'> {
  const seed: Record<string, 'on'> = {};
  for (const svc of services) {
    for (const c of svc.categories) {
      for (const p of c.permissions) {
        if (p.default) seed[rightKey(svc.service, c.id, p)] = 'on';
      }
    }
  }
  return seed;
}

// Full invite management for admins + holders of hp_priv_invite: mint a code, list all codes
// (incl. who redeemed them), and revoke active ones. Admins can additionally attach a rights
// configuration that whoever registers with the code receives automatically. The daemon
// enforces the same gates.
export function InvitesTab({ api, ui, user }: ServiceContextProps) {
  const t = useT();
  const { data, loading, refresh } = useLiveQuery<InvitesResponse>(() => api.get<InvitesResponse>('invites'), 5000);
  const cat = useLiveQuery<CatalogResponse>(() => api.get<CatalogResponse>('catalog'), 30000);
  const grps = useLiveQuery<GroupsResponse>(() => api.get<GroupsResponse>('groups'), 30000);
  const invites = data?.invites ?? [];
  const services = cat.data?.services ?? [];
  const groups = grps.data?.groups ?? [];

  const [note, setNote] = useState('');
  const [days, setDays] = useState('');
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [cfgEnabled, setCfgEnabled] = useState(false);
  const [cfg, setCfg] = useState<RightsConfigValue>({ groups: [], overrides: {} });

  // Seed the config with the current default-on rights the first time the section is enabled —
  // and retry once the catalog has loaded, so opening it before the catalog arrives still
  // pre-fills (parity with how an existing user's defaults show). Never clobbers edits.
  const seeded = useRef(false);
  useEffect(() => {
    if (!cfgEnabled) {
      seeded.current = false;
      return;
    }
    if (!seeded.current && services.length > 0) {
      seeded.current = true;
      setCfg((c) => (c.groups.length === 0 && Object.keys(c.overrides).length === 0 ? { groups: [], overrides: defaultSeed(services) } : c));
    }
  }, [cfgEnabled, services]);

  async function create() {
    setBusy(true);
    try {
      const expiresDays = days.trim() === '' ? 0 : Math.max(0, Math.min(3650, parseInt(days, 10) || 0));
      const payload: Record<string, unknown> = { note: note.trim(), expiresDays };
      if (cfgEnabled) {
        payload.groups = cfg.groups;
        payload.overrides = cfg.overrides;
      }
      const res = await api.post<CreatedInvite>('invites', payload);
      setCreated(res.code);
      setNote('');
      setDays('');
      setCfgEnabled(false);
      setCfg({ groups: [], overrides: {} });
      refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.createCodeError'), description: (e as Error).message, variant: 'error' });
    } finally {
      setBusy(false);
    }
  }

  async function revoke(inv: Invite) {
    const ok = await ui.confirm({
      title: t('privleg.revokeInviteTitle'),
      description: inv.note ? t('privleg.revokeInviteDescNote', { note: inv.note }) : t('privleg.revokeInviteDesc'),
      danger: true,
      confirmLabel: t('privleg.revokeInvite'),
    });
    if (!ok) return;
    try {
      await api.post<{ ok: boolean }>(`invites/${inv.id}/revoke`);
      ui.toast({ title: t('privleg.revoked'), variant: 'success' });
      refresh();
    } catch (e) {
      ui.toast({ title: t('privleg.revokeFailed'), description: (e as Error).message, variant: 'error' });
    }
  }

  const columns: Column<Invite>[] = [
    {
      key: 'note',
      header: t('privleg.colNote'),
      sortable: true,
      sortValue: (i) => i.note.toLowerCase(),
      hideable: false,
      render: (i) => (
        <Stack gap={0}>
          <Stack direction="row" align="center" gap={2}>
            <Text weight="semibold">{i.note || t('privleg.noNote')}</Text>
            {i.hasRights && <Badge variant="accent">{t('privleg.badgeHasRights')}</Badge>}
          </Stack>
          <Text variant="footnote" color="secondary">
            {i.id}
          </Text>
        </Stack>
      ),
    },
    {
      key: 'state',
      header: t('privleg.colStatus'),
      width: 130,
      sortable: true,
      sortValue: (i) => i.state,
      render: (i) => <Badge variant={STATE_VARIANT[i.state]}>{t(STATE_KEY[i.state])}</Badge>,
    },
    {
      key: 'usedBy',
      header: t('privleg.colRedeemedBy'),
      render: (i) => <Text color="secondary">{i.usedBy || '—'}</Text>,
    },
    {
      key: 'created',
      header: t('privleg.colCreated'),
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
      header: t('privleg.colExpires'),
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
            {t('privleg.revokeInvite')}
          </Button>
        ) : null,
    },
  ];

  return (
    <Stack gap={4}>
      <Panel title={t('privleg.createPanelTitle')} className="p-4">
        <Stack gap={3}>
          <Text variant="footnote" color="secondary">
            {t('privleg.createPanelIntro')}
          </Text>
          <Stack direction="row" gap={3} align="end" wrap>
            <Field label={t('privleg.fieldNote')} hint={t('privleg.fieldNoteHint')} className="flex-1 min-w-[200px]">
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder={t('privleg.notePlaceholder')} maxLength={200} />
            </Field>
            <Field label={t('privleg.fieldValidDays')} hint={t('privleg.fieldValidHint')} className="w-[160px]">
              <Input value={days} onChange={(e) => setDays(e.target.value.replace(/[^0-9]/g, ''))} placeholder="0" inputMode="numeric" />
            </Field>
          </Stack>

          {/* Admin-only: attach a rights config that whoever registers with this code receives. */}
          {user.isAdmin && (
            <Stack gap={3}>
              <Checkbox checked={cfgEnabled} onChange={setCfgEnabled} label={t('privleg.inviteRightsToggle')} />
              {cfgEnabled && (
                <Stack gap={3}>
                  <Text variant="footnote" color="secondary">
                    {t('privleg.inviteRightsHint')}
                  </Text>
                  <RightsConfigEditor
                    services={services}
                    groups={groups}
                    value={cfg}
                    onChange={setCfg}
                    canManage={() => true}
                    assignmentEditable
                    confirmDanger={(label) =>
                      ui.confirm({ title: t('privleg.grantTitle', { label }), description: t('privleg.grantDesc'), confirmLabel: t('privleg.grant') })
                    }
                  />
                </Stack>
              )}
            </Stack>
          )}

          <Stack direction="row" justify="end">
            <Button variant="primary" loading={busy} onClick={create}>
              {t('privleg.createCode')}
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
          emptyState={<EmptyState title={t('privleg.noInvites')} description={t('privleg.noInvitesDesc')} />}
        />
      )}

      <Modal
        open={created !== null}
        onOpenChange={(o) => !o && setCreated(null)}
        title={t('privleg.createdModalTitle')}
        description={t('privleg.createdModalDesc')}
        size="sm"
        footer={
          <Button variant="primary" onClick={() => setCreated(null)}>
            {t('privleg.done')}
          </Button>
        }
      >
        <CodeBlock code={created ?? ''} />
      </Modal>
    </Stack>
  );
}
