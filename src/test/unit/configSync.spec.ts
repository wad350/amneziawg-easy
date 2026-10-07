import { beforeEach, describe, expect, test, vi } from 'vitest';

import WireGuard from '../../server/utils/WireGuard';

const state = vi.hoisted(() => ({
  clients: [{ id: 1, name: 'Before', enabled: true, publicKey: 'public' }],
  written: '',
  syncs: [] as string[],
  beforeWrite: null as null | (() => Promise<void>),
  failWrite: false,
  activeWrites: 0,
  maximumWrites: 0,
}));
vi.mock('node:fs/promises', () => ({
  default: {
    writeFile: vi.fn(async (_path: string, body: string) => {
      state.activeWrites++;
      state.maximumWrites = Math.max(state.maximumWrites, state.activeWrites);
      try {
        const before = state.beforeWrite;
        state.beforeWrite = null;
        await before?.();
        if (state.failWrite) {
          state.failWrite = false;
          throw new Error('Synthetic config write failure');
        }
        state.written = body;
      } finally {
        state.activeWrites--;
      }
    }),
  },
}));
vi.mock('#server/utils/Database', () => ({
  default: {
    interfaces: { get: vi.fn(async () => ({ name: 'wg0' })) },
    clients: { getAll: vi.fn(async () => structuredClone(state.clients)) },
    hooks: { get: vi.fn(async () => ({})) },
    userConfigs: { get: vi.fn(async () => ({})) },
  },
}));
vi.mock('#server/utils/config', () => ({
  WG_ENV: { DATA_DIR: '/unused-unit-only', DISABLE_IPV6: true },
  OLD_ENV: {},
}));
vi.mock('#server/utils/firewall', () => ({
  firewall: { rebuildRules: vi.fn(async () => {}) },
}));
vi.mock('#server/utils/wgHelper', () => ({
  wg: {
    generateServerInterface: vi.fn(() => '[Server]'),
    generateServerPeer: vi.fn((peer: { name: string }) => `Peer:${peer.name}`),
    sync: vi.fn(async () => {
      state.syncs.push(state.written);
    }),
    restart: vi.fn(() => {
      throw new Error('Config synchronization must not restart the interface');
    }),
  },
}));
vi.mock('#server/utils/routingContext', () => ({ getRoutingContext: vi.fn() }));
vi.mock('#server/utils/routingRuntime', () => ({
  armAppliedRoutingGate: vi.fn(),
  startRouting: vi.fn(),
  stopRouting: vi.fn(),
}));

beforeEach(() => {
  state.clients = [
    { id: 1, name: 'Before', enabled: true, publicKey: 'public' },
  ];
  state.written = '';
  state.syncs = [];
  state.beforeWrite = null;
  state.failWrite = false;
  state.activeWrites = 0;
  state.maximumWrites = 0;
});

describe('WireGuard configuration synchronization queue', () => {
  test('queued writes read fresh client state and cannot interleave or finish with stale peer data', async () => {
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => (release = resolve));
    const started = new Promise<void>((resolve) => (entered = resolve));
    state.beforeWrite = async () => {
      entered();
      await blocked;
    };
    const first = WireGuard.saveConfig();
    await started;
    state.clients[0]!.name = 'After';
    const second = WireGuard.saveConfig();
    release();
    await Promise.all([first, second]);
    expect(state.maximumWrites).toBe(1);
    expect(state.syncs).toEqual([
      '[Server]\n\nPeer:Before\n\n',
      '[Server]\n\nPeer:After\n\n',
    ]);
    expect(state.written).toBe(state.syncs[1]);
  });
  test('one rejected write is reported to its caller while subsequent synchronization still succeeds', async () => {
    state.failWrite = true;
    const results = await Promise.allSettled([
      WireGuard.saveConfig(),
      WireGuard.saveConfig(),
    ]);
    expect(results[0]).toMatchObject({
      status: 'rejected',
      reason: expect.any(Error),
    });
    expect(results[1]!.status).toBe('fulfilled');
    expect(state.maximumWrites).toBe(1);
    expect(state.syncs).toEqual(['[Server]\n\nPeer:Before\n\n']);
  });
});
