import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import {
  assertAwgIsolation,
  awgBackend,
  awgIsolationMarker,
} from '../../server/utils/runtimeIsolation';

const mocked = vi.hoisted(() => ({
  access: vi.fn(),
  readFile: vi.fn(),
  writeFile: vi.fn(),
  run: vi.fn(),
}));
vi.mock('node:fs/promises', () => ({
  default: {
    access: mocked.access,
    readFile: mocked.readFile,
    writeFile: mocked.writeFile,
  },
}));
vi.mock('node:child_process', () => ({
  execFile: Object.assign(vi.fn(), {
    [Symbol.for('nodejs.util.promisify.custom')]: mocked.run,
  }),
}));

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
let device: {
  ifindex: number;
  link_index?: number;
  linkinfo?: { info_kind: string };
};
let links: Array<{ ifname: string; linkinfo: { info_kind: string } }>;

beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv('AWG_BACKEND', 'userspace');
  vi.stubEnv('AWG_FORCE_USERSPACE', 'true');
  Object.defineProperty(process, 'platform', { value: 'linux' });
  device = { ifindex: 2, link_index: 123, linkinfo: { info_kind: 'veth' } };
  links = [];
  mocked.access.mockResolvedValue(undefined);
  mocked.writeFile.mockResolvedValue(undefined);
  mocked.readFile.mockResolvedValue('CapEff:\t0000000000001000\n');
  mocked.run.mockImplementation(async (_file: string, args: string[]) => ({
    stdout: JSON.stringify(args.includes('eth0') ? [device] : links),
  }));
});
afterEach(() => {
  Object.defineProperty(process, 'platform', platform);
  vi.unstubAllEnvs();
});

describe('isolated inbound AWG backends', () => {
  test('defaults to Go and requires a recognized explicit kernel selection', () => {
    expect(awgBackend({})).toBe('userspace');
    expect(awgBackend({ AWG_FORCE_USERSPACE: 'true' })).toBe('userspace');
    expect(
      awgBackend({ AWG_BACKEND: 'kernel', AWG_FORCE_USERSPACE: 'true' })
    ).toBe('kernel');
    expect(() => awgBackend({ AWG_BACKEND: 'auto' })).toThrow(
      'AWG_BACKEND must be userspace or kernel'
    );
  });
  test('keeps the existing Go marker and TUN guard for rollback', async () => {
    links = [{ ifname: 'wg0', linkinfo: { info_kind: 'tun' } }];
    await assertAwgIsolation(true);
    expect(mocked.writeFile).toHaveBeenCalledWith(
      '/run/awg-easy-isolated-network',
      'bridge-tun-v1\n',
      { mode: 0o600 }
    );
    expect(mocked.access).not.toHaveBeenCalledWith('/sys/module/amneziawg');
  });
  test('allows only an AmneziaWG kernel link after checking the loaded module', async () => {
    vi.stubEnv('AWG_BACKEND', 'kernel');
    links = [{ ifname: 'wg0', linkinfo: { info_kind: 'amneziawg' } }];
    await assertAwgIsolation(true);
    expect(mocked.access).toHaveBeenCalledWith('/sys/module/amneziawg');
    expect(mocked.access).toHaveBeenCalledWith('/dev/net/tun');
    expect(mocked.writeFile).toHaveBeenCalledWith(
      '/run/awg-easy-isolated-network',
      `${awgIsolationMarker('kernel')}\n`,
      { mode: 0o600 }
    );
  });
  test('refuses an unavailable kernel module before interface commands or writes', async () => {
    vi.stubEnv('AWG_BACKEND', 'kernel');
    mocked.access.mockImplementation(async (path: string) => {
      if (path === '/sys/module/amneziawg') throw new Error('ENOENT');
    });
    await expect(assertAwgIsolation(true)).rejects.toThrow('already loaded');
    expect(mocked.run).not.toHaveBeenCalled();
    expect(mocked.writeFile).not.toHaveBeenCalled();
  });
  test.each(['userspace', 'kernel'])(
    '%s rejects host networking',
    async (backend) => {
      vi.stubEnv('AWG_BACKEND', backend);
      device = { ifindex: 2, linkinfo: { info_kind: 'ether' } };
      await expect(assertAwgIsolation(true)).rejects.toThrow(
        'separate Docker bridge'
      );
      expect(mocked.writeFile).not.toHaveBeenCalled();
    }
  );
  test.each(['userspace', 'kernel'])(
    '%s rejects SYS_MODULE',
    async (backend) => {
      vi.stubEnv('AWG_BACKEND', backend);
      mocked.readFile.mockResolvedValue('CapEff:\t0000000000011000\n');
      await expect(assertAwgIsolation(true)).rejects.toThrow('SYS_MODULE');
      expect(mocked.writeFile).not.toHaveBeenCalled();
    }
  );
  test.each([
    ['userspace', 'amneziawg'],
    ['kernel', 'tun'],
    ['kernel', 'wireguard'],
  ])('%s refuses to replace an existing %s wg0', async (backend, kind) => {
    vi.stubEnv('AWG_BACKEND', backend);
    links = [{ ifname: 'wg0', linkinfo: { info_kind: kind } }];
    await expect(assertAwgIsolation(true)).rejects.toThrow(
      'will not be modified'
    );
    expect(mocked.writeFile).not.toHaveBeenCalled();
  });
  test('non-Linux startup fails without touching runtime files', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' });
    await expect(assertAwgIsolation(true)).rejects.toThrow('requires Linux');
    expect(mocked.access).not.toHaveBeenCalled();
    expect(mocked.writeFile).not.toHaveBeenCalled();
  });
});
