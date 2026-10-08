import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

export type AwgBackend = 'userspace' | 'kernel';

/** Backend selection must be explicit; an absent flag keeps the Go default. */
export function awgBackend(
  environment: NodeJS.ProcessEnv = process.env
): AwgBackend {
  const backend = environment.AWG_BACKEND || 'userspace';
  if (backend !== 'userspace' && backend !== 'kernel') {
    throw new Error('AWG_BACKEND must be userspace or kernel');
  }
  return backend;
}

export function awgIsolationMarker(backend: AwgBackend): string {
  return backend === 'kernel' ? 'bridge-amneziawg-v1' : 'bridge-tun-v1';
}

export async function assertAwgBackendAvailable(backend: AwgBackend) {
  // Egresses remain userspace, including when the inbound uses the kernel.
  await fs.access('/dev/net/tun');
  if (backend === 'kernel') {
    try {
      await fs.access('/sys/module/amneziawg');
    } catch {
      throw new Error('Kernel AWG requires an already loaded amneziawg module');
    }
  }
}

/** Refuse accidental operation in the host namespace before touching interfaces. */
export async function assertAwgIsolation(enabled: boolean) {
  if (!enabled) return;
  if (process.platform !== 'linux') {
    throw new Error('Isolated AWG runtime requires Linux');
  }
  await fs.access('/.dockerenv');
  const backend = awgBackend();
  await assertAwgBackendAvailable(backend);
  const { stdout } = await run('ip', [
    '-j',
    '-d',
    'link',
    'show',
    'dev',
    'eth0',
  ]);
  const interfaces = JSON.parse(stdout) as {
    linkinfo?: { info_kind?: string };
    ifindex: number;
    link_index?: number;
  }[];
  const device = interfaces[0];
  if (
    !device ||
    (device.linkinfo?.info_kind !== 'veth' &&
      (!device.link_index || device.link_index === device.ifindex))
  ) {
    throw new Error('AWG requires a separate Docker bridge namespace');
  }
  const status = await fs.readFile('/proc/self/status', 'utf8');
  const caps = status.match(/^CapEff:\s*([0-9a-f]+)$/m)?.[1];
  if (!caps || (BigInt(`0x${caps}`) & (1n << 16n)) !== 0n) {
    throw new Error('SYS_MODULE capability is forbidden for isolated AWG');
  }
  const links = JSON.parse(
    (await run('ip', ['-j', '-d', 'link', 'show'])).stdout
  ) as { ifname: string; linkinfo?: { info_kind?: string } }[];
  const existing = links.find((link) => link.ifname === 'wg0');
  const expectedKind = backend === 'kernel' ? 'amneziawg' : 'tun';
  if (existing && existing.linkinfo?.info_kind !== expectedKind) {
    throw new Error(`An existing non-${expectedKind} wg0 will not be modified`);
  }
  await fs.writeFile(
    '/run/awg-easy-isolated-network',
    `${awgIsolationMarker(backend)}\n`,
    { mode: 0o600 }
  );
}
