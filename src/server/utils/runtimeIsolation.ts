import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** Refuse accidental operation in the host namespace before touching interfaces. */
export async function assertAwgIsolation(enabled: boolean) {
  if (!enabled) return;
  if (process.platform !== 'linux') {
    throw new Error('Isolated AWG runtime requires Linux');
  }
  await fs.access('/.dockerenv');
  await fs.access('/dev/net/tun');
  if (process.env.AWG_FORCE_USERSPACE !== 'true') {
    throw new Error('Isolated AWG requires AWG_FORCE_USERSPACE=true');
  }
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
  if (existing && existing.linkinfo?.info_kind !== 'tun') {
    throw new Error('An existing non-TUN wg0 will not be modified');
  }
  await fs.writeFile('/run/awg-easy-isolated-network', 'bridge-tun-v1\n', {
    mode: 0o600,
  });
}
