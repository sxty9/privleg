import { Badge, Panel, Stack, Text, useT, type PermissionDecl, type PermissionManifest } from '@holistic/ui';
import type { ReactNode } from 'react';

// One declared right, flattened with its localized label and its storage key. The key is the
// backing hp_* group for a normal right, or the fully-qualified "svc:cat:id" for a shell
// right (which has no group — the login shell is the source of truth). This is the same key
// the backend stores in group definitions and per-user overrides.
export interface CatalogRight {
  service: string;
  category: string;
  perm: PermissionDecl;
  key: string;
  label: string;
}

interface Props {
  services: PermissionManifest[];
  /** Trailing control for each right (a two-state Switch for groups, a tri-state for users). */
  control: (right: CatalogRight) => ReactNode;
  /** Shown when no service declares any rights. */
  emptyText?: string;
}

export function rightKey(service: string, categoryId: string, p: PermissionDecl): string {
  return p.type === 'shell' ? `${service}:${categoryId}:${p.id}` : (p.group ?? '');
}

// Shared rights-catalog renderer: walks services → categories → permissions and renders the
// identical Panel/label/badge layout used by both the group editor and the per-user editor.
// Only the trailing control differs, supplied via the `control` render prop. Rights labels
// come from each service's manifest but are localized by their stable id, falling back to the
// manifest text — exactly as the original per-user editor did.
export function RightsCatalog({ services, control, emptyText }: Props) {
  const t = useT();
  const tr = (key: string, fallback: string) => (t.has(key) ? t(key) : fallback);

  if (services.length === 0) {
    return <Text color="secondary">{emptyText ?? ''}</Text>;
  }

  return (
    <>
      {services.flatMap((svc) =>
        svc.categories.map((c) => (
          <Panel
            key={`${svc.service}:${c.id}`}
            title={`${tr(`rights.cat.${svc.service}.${c.id}`, c.label)} · ${tr(`service.${svc.service}`, svc.service)}`}
            className="p-4"
          >
            <Stack gap={3}>
              {c.description && (
                <Text variant="footnote" color="secondary">
                  {tr(`rights.catdesc.${svc.service}.${c.id}`, c.description)}
                </Text>
              )}
              {c.permissions.map((p) => {
                const label = tr(`rights.perm.${svc.service}.${c.id}.${p.id}`, p.label);
                const right: CatalogRight = { service: svc.service, category: c.id, perm: p, key: rightKey(svc.service, c.id, p), label };
                return (
                  <Stack key={right.key} direction="row" align="center" justify="between" gap={3}>
                    <Stack gap={1}>
                      <Stack direction="row" align="center" gap={2}>
                        <Text weight="semibold">{label}</Text>
                        {p.dangerous && <Badge variant="warning">{t('privleg.badgeDangerous')}</Badge>}
                        {/* orange (the `net` token), distinct from the dangerous badge's amber `warning` */}
                        {p.sensitive && <Badge className="bg-net/15 text-net">{t('privleg.badgeSensitive')}</Badge>}
                        {p.default && <Badge variant="neutral">{t('privleg.badgeDefaultOn')}</Badge>}
                      </Stack>
                      {p.description && (
                        <Text variant="footnote" color="secondary">
                          {tr(`rights.permdesc.${svc.service}.${c.id}.${p.id}`, p.description)}
                        </Text>
                      )}
                    </Stack>
                    {control(right)}
                  </Stack>
                );
              })}
            </Stack>
          </Panel>
        )),
      )}
    </>
  );
}
