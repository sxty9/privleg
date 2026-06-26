import {
  Badge,
  Box,
  Checkbox,
  Panel,
  SegmentedControl,
  Stack,
  Switch,
  Text,
  useT,
  type PermissionManifest,
  type SegmentedOption,
} from '@holistic/ui';
import { RightsCatalog, type CatalogRight } from './RightsCatalog';
import type { OverrideState, RightsGroup } from './types';

// The three states of a per-right switch: force-off, inherit-from-groups, force-on.
type TriState = 'off' | 'group' | 'on';

// A rights configuration: assigned rights-group ids + per-right manual overrides. The exact
// shape stored per user AND attached to an invite.
export interface RightsConfigValue {
  groups: string[];
  overrides: Record<string, OverrideState>;
}

interface Props {
  services: PermissionManifest[];
  groups: RightsGroup[];
  value: RightsConfigValue;
  onChange: (value: RightsConfigValue) => void;
  /** Whether the three-way control for a service's rights is editable. */
  canManage: (service: string) => boolean;
  /** Whether the group-assignment checkboxes are editable (else shown read-only). */
  assignmentEditable: boolean;
  /** Optional confirm before forcing a dangerous right on (returns false to cancel). */
  confirmDanger?: (label: string) => Promise<boolean>;
}

// The shared rights editor: a group-assignment block on top, then the full catalog with a
// three-way switch (Off / Group / On) per right. Fully controlled — `inherited` (what the
// "Group" state resolves to) is computed client-side from the assigned groups, so the same
// component drives the per-user editor and the per-invite template identically.
export function RightsConfigEditor({ services, groups, value, onChange, canManage, assignmentEditable, confirmDanger }: Props) {
  const t = useT();
  const assigned = new Set(value.groups);
  // What the "Group" state yields per right: the union of the assigned groups' rights.
  const inherited = new Set(value.groups.flatMap((gid) => groups.find((g) => g.id === gid)?.rights ?? []));

  const toggleGroup = (id: string, on: boolean) => {
    onChange({ ...value, groups: on ? [...value.groups, id] : value.groups.filter((g) => g !== id) });
  };

  const setTri = async (right: CatalogRight, next: TriState) => {
    if (next === 'on' && right.perm.dangerous && confirmDanger) {
      const ok = await confirmDanger(right.label);
      if (!ok) return;
    }
    const overrides: Record<string, OverrideState> = { ...value.overrides };
    if (next === 'group') delete overrides[right.key];
    else overrides[right.key] = next;
    onChange({ ...value, overrides });
  };

  const control = (right: CatalogRight) => {
    const disabled = !canManage(right.service);
    // With no group assigned there is nothing to inherit, so the middle "Group" state is
    // meaningless (always "Group · off"). Fall back to a plain Off/On switch: on = force-on,
    // off = no override (which, without groups, resolves to off).
    if (value.groups.length === 0) {
      const on = value.overrides[right.key] === 'on';
      return <Switch checked={on} disabled={disabled} onChange={(next) => setTri(right, next ? 'on' : 'group')} />;
    }
    const v: TriState = value.overrides[right.key] ?? 'group';
    const groupYields = inherited.has(right.key);
    const options: SegmentedOption<TriState>[] = [
      { value: 'off', label: t('privleg.triOff') },
      { value: 'group', label: groupYields ? t('privleg.triGroupOn') : t('privleg.triGroupOff') },
      { value: 'on', label: t('privleg.triOn') },
    ];
    return (
      <Box className={disabled ? 'pointer-events-none opacity-50' : undefined}>
        <SegmentedControl options={options} value={v} onChange={(x) => setTri(right, x)} />
      </Box>
    );
  };

  return (
    <Stack gap={4}>
      <Panel title={t('privleg.assignGroupsTitle')} className="p-4">
        <Stack gap={3}>
          <Text variant="footnote" color="secondary">
            {t('privleg.assignGroupsIntro')}
          </Text>
          {groups.length === 0 ? (
            <Text variant="footnote" color="secondary">
              {t('privleg.noGroupsYet')}
            </Text>
          ) : assignmentEditable ? (
            <Stack gap={2}>
              {groups.map((g) => (
                <Checkbox key={g.id} checked={assigned.has(g.id)} onChange={(next) => toggleGroup(g.id, next)} label={g.label} />
              ))}
            </Stack>
          ) : (
            <Stack direction="row" gap={2} wrap>
              {value.groups.length === 0 ? (
                <Text variant="footnote" color="secondary">
                  {t('privleg.noGroupsAssigned')}
                </Text>
              ) : (
                groups.filter((g) => assigned.has(g.id)).map((g) => (
                  <Badge key={g.id} variant="neutral">
                    {g.label}
                  </Badge>
                ))
              )}
            </Stack>
          )}
        </Stack>
      </Panel>

      <RightsCatalog services={services} control={control} emptyText={t('privleg.noServiceRights')} />
    </Stack>
  );
}
