import { beforeEach, describe, expect, test, vi } from 'vitest';

import type { ClientType } from '../../server/database/repositories/client/types';
import type { InterfaceType } from '../../server/database/repositories/interface/types';
import type { UserConfigType } from '../../server/database/repositories/userConfig/types';
import { RoutingConfigSchema } from '../../shared/types/routing';
import { IntegrationRulesUpdateSchema } from '../../shared/types/integrationApi';
import {
  IntegrationClientCreateSchema,
  IntegrationClientIdSchema,
  IntegrationClientPatchSchema,
} from '../../server/utils/integrationApiSchemas';
import {
  toIntegrationClient,
  toIntegrationRouting,
} from '../../server/utils/integrationApi';
import {
  mergeRoutingRules,
  routingRevision,
  RoutingRevisionConflict,
} from '../../server/utils/routingRevision';
import {
  saveAndApplyRouting,
  saveRoutingRulesWithRevision,
} from '../../server/utils/routingRuntime';

const storage = vi.hoisted(() => ({
  draft: {} as unknown,
  applied: {} as unknown,
  failNext: false,
  beforeSave: null as null | (() => Promise<void>),
}));
vi.mock('../../server/utils/routingStore', () => ({
  ROUTING_DATA_DIR: '/unused-unit-only',
  loadRoutingConfig: vi.fn(async () => structuredClone(storage.draft)),
  loadAppliedRoutingConfig: vi.fn(async () => structuredClone(storage.applied)),
  saveRoutingConfig: vi.fn(async (config: unknown) => {
    await storage.beforeSave?.();
    if (storage.failNext) {
      storage.failNext = false;
      throw new Error('Synthetic storage failure');
    }
    storage.draft = structuredClone(config);
  }),
  saveAppliedRoutingConfig: vi.fn(async (config: unknown) => {
    storage.applied = structuredClone(config);
  }),
  writeRoutingFile: vi.fn(async () => {}),
}));

const iface = {
  name: 'wg0',
  privateKey: 'hidden-server-private',
  publicKey: 'server-public',
  awgSettings: {
    headerProtectionKey: 'hidden-shared-header-key',
    contentPaddingAddition: '15-53',
    randomTrailers: true,
    disableCookies: false,
  },
  jC: 4,
  jMin: 59,
  jMax: 202,
  s1: 16,
  s2: 16,
  s3: 16,
  s4: 16,
  h1: '1',
  h2: '2',
  h3: '3',
  h4: '4',
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
} as InterfaceType;
const defaults = {
  defaultDns: ['192.0.2.53'],
  defaultAllowedIps: ['0.0.0.0/0'],
  defaultJC: 99,
  defaultI1: '<b ff>',
} as UserConfigType;
const client: ClientType = {
  id: 21,
  userId: 1,
  interfaceId: 'wg0',
  name: 'Laptop',
  privateKey: 'hidden-client-private',
  publicKey: 'client-public',
  preSharedKey: '',
  ipv4Address: '172.31.80.2',
  ipv6Address: 'fd31:80::2',
  preUp: 'hidden-existing-hook',
  postUp: '',
  preDown: '',
  postDown: '',
  enabled: true,
  expiresAt: null,
  createdAt: '2026-01-01',
  updatedAt: '2026-01-01',
  dns: null,
  allowedIps: null,
  serverAllowedIps: [],
  firewallIps: null,
  mtu: 1340,
  persistentKeepalive: 0,
  serverEndpoint: null,
  jC: null,
  jMin: null,
  jMax: null,
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
  awgSettings: { persistentKeepaliveRange: '20-30' },
};
const rule = {
  id: 'selected',
  name: 'Selected destinations',
  enabled: true,
  networks: ['tcp'] as const,
  ports: ['443'],
  suffixes: ['example.com'],
  outbound: 'direct',
};
const config = () =>
  RoutingConfigSchema.parse({
    enabled: false,
    rules: [rule],
  });
const context = {
  inboundInterface: 'wg0',
  sourceCidr: '172.31.80.0/24',
  inboundPort: 38472,
};

beforeEach(() => {
  storage.draft = config();
  storage.applied = RoutingConfigSchema.parse({});
  storage.failNext = false;
  storage.beforeSave = null;
});

describe('integration API client contract', () => {
  test('rejects immutable credentials, hooks and empty patches instead of ignoring them', () => {
    for (const data of [
      {},
      { name: 'Changed', privateKey: 'forbidden' },
      { name: 'Changed', preSharedKey: 'forbidden' },
      { ipv4Address: '172.31.80.9' },
      { postUp: 'forbidden' },
      { awgSettings: { headerProtectionKey: 'forbidden' } },
    ])
      expect(IntegrationClientPatchSchema.safeParse(data).success).toBe(false);
    expect(IntegrationClientIdSchema.safeParse({ clientId: -1 }).success).toBe(
      false
    );
    expect(IntegrationClientIdSchema.safeParse({ clientId: 1.5 }).success).toBe(
      false
    );
    expect(IntegrationClientIdSchema.parse({ clientId: '21' }).clientId).toBe(
      21
    );
  });
  test('create accepts inherited defaults but rejects shared crypto overrides', () => {
    expect(IntegrationClientCreateSchema.parse({ name: 'New laptop' })).toEqual(
      {
        name: 'New laptop',
        expiresAt: null,
      }
    );
    for (const data of [
      { name: 'New laptop', privateKey: 'forbidden' },
      { name: 'New laptop', awgSettings: { randomTrailers: true } },
      { name: 'New laptop', expiresAt: 'not-a-date' },
    ])
      expect(IntegrationClientCreateSchema.safeParse(data).success).toBe(false);
  });
  test('DTO exposes effective DNS/routes and runtime status without nested secrets or links', () => {
    const dto = toIntegrationClient(
      {
        ...client,
        oneTimeLink: 'hidden-one-time-link',
        endpoint: '198.51.100.1:1234',
        transferRx: 10,
        transferTx: 20,
      },
      iface,
      defaults,
      { enableIpv6: false }
    );
    expect(dto).toMatchObject({
      dns: defaults.defaultDns,
      allowedIps: defaults.defaultAllowedIps,
      ipv6Address: null,
      endpoint: '198.51.100.1:1234',
      persistentKeepalive: '20-30',
      transferRx: 10,
      transferTx: 20,
    });
    expect(dto.awg.jC).toBeNull();
    expect(dto.awg.i1).toBeNull();
    const encoded = JSON.stringify(dto);
    for (const secret of [
      client.privateKey,
      'hidden-one-time-link',
      'hidden-shared-header-key',
      client.preUp,
      iface.privateKey,
    ])
      expect(encoded).not.toContain(secret);
    expect(dto).not.toHaveProperty('preSharedKey');
    expect(dto.awg.settings).not.toHaveProperty('headerProtectionKey');
  });
});

describe('integration routing revisions and private profiles', () => {
  test('redacts outbound profiles and keeps complete profiles during a rule-only merge', () => {
    const current = config();
    current.egresses = [
      {
        id: 'remote',
        name: 'Remote',
        independentPeer: true,
        profile: 'hidden-outbound-profile-and-private-key',
      },
    ];
    const revision = routingRevision(current);
    const update = IntegrationRulesUpdateSchema.parse({
      revision,
      rules: [{ ...rule, outbound: 'remote' }],
      enabled: true,
    });
    const merged = mergeRoutingRules(current, update);
    expect(merged.egresses).toEqual(current.egresses);
    expect(merged.enabled).toBe(true);
    expect(current.enabled).toBe(false);
    const publicData = toIntegrationRouting(merged, {
      enabled: false,
      state: 'stopped',
      pid: null,
      appliedAt: null,
      error: null,
    });
    expect(publicData.egresses).toEqual([{ id: 'remote', name: 'Remote' }]);
    expect(JSON.stringify(publicData)).not.toContain('hidden-outbound-profile');
    expect(() => mergeRoutingRules(merged, { ...update, revision })).toThrow(
      RoutingRevisionConflict
    );
  });
  test('revision covers private profile and ordering changes while ignoring object key order', () => {
    const current = config();
    const original = routingRevision(current);
    expect(
      routingRevision({
        rules: current.rules,
        egresses: current.egresses,
        enabled: current.enabled,
        version: current.version,
      })
    ).toBe(original);
    current.egresses.push({
      id: 'remote',
      name: 'Remote',
      independentPeer: true,
      profile: 'first-profile',
    });
    const withProfile = routingRevision(current);
    current.egresses[0]!.profile = 'second-profile';
    expect(routingRevision(current)).not.toBe(withProfile);
    expect(routingRevision(current)).not.toBe(original);
  });
  test('a preceding legacy write makes a queued v1 revision stale rather than overwriting it', async () => {
    const original = config();
    const legacy = config();
    legacy.rules[0]!.name = 'Changed in the web editor';
    let releaseSave!: () => void;
    let enteredSave!: () => void;
    const entered = new Promise<void>((resolve) => (enteredSave = resolve));
    const blocked = new Promise<void>((resolve) => (releaseSave = resolve));
    storage.beforeSave = async () => {
      enteredSave();
      await blocked;
    };
    const first = saveAndApplyRouting(legacy, context, false);
    await entered;
    const second = saveRoutingRulesWithRevision(
      IntegrationRulesUpdateSchema.parse({
        revision: routingRevision(original),
        rules: [],
      }),
      context
    );
    const expectedConflict = expect(second).rejects.toBeInstanceOf(
      RoutingRevisionConflict
    );
    releaseSave();
    await first;
    await expectedConflict;
    expect(storage.draft).toEqual(legacy);
  });
  test('concurrent v1 writes with the same revision allow only the first', async () => {
    const update = IntegrationRulesUpdateSchema.parse({
      revision: routingRevision(config()),
      rules: [],
    });
    const results = await Promise.allSettled([
      saveRoutingRulesWithRevision(update, context),
      saveRoutingRulesWithRevision(update, context),
    ]);
    expect(results[0]!.status).toBe('fulfilled');
    expect(results[1]).toMatchObject({
      status: 'rejected',
      reason: expect.any(RoutingRevisionConflict),
    });
    expect(storage.draft).toMatchObject({ rules: [] });
  });
  test('a failed draft save rolls back through the existing routing transaction', async () => {
    const original = config();
    storage.failNext = true;
    await expect(
      saveRoutingRulesWithRevision(
        IntegrationRulesUpdateSchema.parse({
          revision: routingRevision(original),
          rules: [],
        }),
        context
      )
    ).rejects.toThrow('Private routing save failed');
    expect(storage.draft).toEqual(original);
    expect(storage.applied).toEqual(RoutingConfigSchema.parse({}));
  });
});
