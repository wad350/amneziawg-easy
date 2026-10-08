import { isIPv4 } from 'node:net';
import { createHash } from 'node:crypto';

import {
  RoutingConfigSchema,
  type RoutingConfig,
} from '../../shared/types/routing';

import { cpsPacketSize } from './amneziawg';

export interface RoutingContext {
  inboundInterface: string;
  sourceCidr: string;
  inboundPort?: number;
  inboundPrivateKeys?: string[];
}

export interface ImportedAwgProfile {
  address: string;
  mtu: number;
  interface: Record<string, string>;
  peer: Record<string, string>;
}

export class RoutingValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RoutingValidationError';
  }
}

function requireValid(condition: unknown, message: string): asserts condition {
  if (!condition) throw new RoutingValidationError(message);
}

export function ipv4Number(ip: string): number {
  requireValid(isIPv4(ip), 'Expected IPv4 address');
  return ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);
}

export function ipv4Cidr(value: string): {
  start: number;
  end: number;
  prefix: number;
} {
  const [ip, rawPrefix, ...extra] = value.split('/');
  requireValid(
    ip && rawPrefix && !extra.length && /^\d{1,2}$/.test(rawPrefix),
    'Expected IPv4 CIDR'
  );
  const prefix = Number(rawPrefix);
  requireValid(prefix <= 32, 'Invalid IPv4 prefix');
  const number = ipv4Number(ip);
  const size = 2 ** (32 - prefix);
  const start = Math.floor(number / size) * size;
  return { start, end: start + size - 1, prefix };
}

export function overlaps(a: string, b: string): boolean {
  const x = ipv4Cidr(a);
  const y = ipv4Cidr(b);
  return x.start <= y.end && y.start <= x.end;
}

function validKey(value: string): boolean {
  return (
    /^[A-Za-z0-9+/]{43}=$/.test(value) &&
    Buffer.from(value, 'base64').length === 32 &&
    Buffer.from(value, 'base64').toString('base64') === value
  );
}

const awgParameters = new Set([
  'Jc',
  'Jmin',
  'Jmax',
  'S1',
  'S2',
  'S3',
  'S4',
  'H1',
  'H2',
  'H3',
  'H4',
  'I1',
  'I2',
  'I3',
  'I4',
  'I5',
  'HeaderProtectionKey',
  'ContentPaddingAddition',
  'RandomTrailers',
  'DisableCookies',
  'RekeyAfterTime',
  'RekeyTimeout',
  'RejectAfterTime',
  'KeepaliveTimeout',
  'MaxHandshakeAttempts',
]);
const interfaceFields = new Set([
  'PrivateKey',
  'Address',
  'MTU',
  'ListenPort',
  'Table',
  'DNS',
  ...awgParameters,
]);
const peerFields = new Set([
  'PublicKey',
  'PresharedKey',
  'AllowedIPs',
  'Endpoint',
  'PersistentKeepalive',
]);

function range(value: string, max: number, min = 0): boolean {
  if (!/^\d+(?:-\d+)?$/.test(value)) return false;
  const [low, high = low] = value.split('-').map(Number);
  return low! >= min && high! <= max && low! <= high!;
}

/** No shell hooks, implicit host routes, multiple peers or unknown extension fields. */
export function parseAwgProfile(text: string): ImportedAwgProfile {
  requireValid(
    Buffer.byteLength(text) <= 262144 && !text.includes('\0'),
    'AWG profile exceeds import limits'
  );
  const iface: Record<string, string> = {};
  const peer: Record<string, string> = {};
  let section: 'Interface' | 'Peer' | null = null;
  let peerCount = 0;
  let interfaceCount = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (line === '[Interface]') {
      requireValid(
        ++interfaceCount === 1 && peerCount === 0,
        'Expected one Interface followed by one Peer'
      );
      section = 'Interface';
      continue;
    }
    if (line === '[Peer]') {
      requireValid(
        interfaceCount === 1 && ++peerCount === 1,
        'Exactly one independent outbound peer is allowed'
      );
      section = 'Peer';
      continue;
    }
    const match = /^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.+)$/.exec(line);
    requireValid(
      section && match && match[1] && match[2],
      'Malformed AWG profile field'
    );
    const key = match[1];
    const value = match[2].trim();
    const fields = section === 'Interface' ? interfaceFields : peerFields;
    requireValid(fields.has(key), 'Unsupported or unsafe AWG profile field');
    const target = section === 'Interface' ? iface : peer;
    // eslint-disable-next-line no-control-regex
    const invalidControlChars = /[\r\n\x00-\x1f\x7f]/.test(value);
    requireValid(
      !Object.hasOwn(target, key) &&
        value.length <= 8192 &&
        !invalidControlChars,
      'Duplicate or invalid AWG profile field'
    );
    target[key] = value;
  }
  requireValid(
    interfaceCount === 1 && peerCount === 1,
    'Expected one Interface and one Peer'
  );
  requireValid(
    validKey(iface.PrivateKey ?? '') && validKey(peer.PublicKey ?? ''),
    'Invalid AWG key encoding'
  );
  requireValid(
    Buffer.from(iface.PrivateKey!, 'base64').some((byte) => byte !== 0) &&
      Buffer.from(peer.PublicKey!, 'base64').some((byte) => byte !== 0),
    'AWG private and public keys must not be zero'
  );
  if (peer.PresharedKey)
    requireValid(
      validKey(peer.PresharedKey),
      'Invalid AWG preshared key encoding'
    );
  const address = iface.Address ?? '';
  ipv4Cidr(address);
  requireValid(
    !overlaps(address, '10.0.0.0/8'),
    'Outbound address must be one IPv4 CIDR outside 10.0.0.0/8'
  );
  requireValid(
    !['0.0.0.0', '127.0.0.1'].includes(address.split('/')[0]!),
    'Invalid outbound address'
  );
  const endpoint = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(
    peer.Endpoint ?? ''
  );
  requireValid(
    endpoint &&
      isIPv4(endpoint[1]!) &&
      Number(endpoint[2]) >= 1 &&
      Number(endpoint[2]) <= 65535,
    'Outbound endpoint must be a numeric IPv4 address and port'
  );
  requireValid(
    !/^(0|10|127)\./.test(endpoint[1]!),
    'Outbound endpoint must not use loopback, unspecified or 10.0.0.0/8'
  );
  requireValid(
    peer.AllowedIPs?.replace(/\s/g, '') === '0.0.0.0/0',
    'Outbound peer AllowedIPs must be 0.0.0.0/0; Table=off is enforced'
  );
  requireValid(
    iface.Table === undefined || iface.Table === 'off',
    'Outbound routes must use Table=off'
  );
  const mtu = Number(iface.MTU ?? '1340');
  requireValid(
    Number.isInteger(mtu) && mtu >= 1280 && mtu <= 1500,
    'Invalid outbound MTU'
  );
  if (iface.ListenPort)
    requireValid(range(iface.ListenPort, 65535), 'Invalid outbound ListenPort');
  if (peer.PersistentKeepalive)
    requireValid(
      range(peer.PersistentKeepalive, 65535),
      'Invalid persistent keepalive range'
    );
  for (const key of ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4']) {
    if (iface[key])
      requireValid(
        range(iface[key], key === 'Jc' ? 128 : 65535) &&
          !iface[key]!.includes('-'),
        'Invalid AWG padding parameter'
      );
  }
  if (iface.Jmin && iface.Jmax)
    requireValid(
      Number(iface.Jmin) <= Number(iface.Jmax),
      'Jmin must not exceed Jmax'
    );
  const headerRanges: Array<[number, number]> = [];
  for (const key of ['H1', 'H2', 'H3', 'H4'])
    if (iface[key]) {
      requireValid(
        range(iface[key], 4294967295),
        'Invalid AWG uint32 header range'
      );
      const [low, high = low] = iface[key]!.split('-').map(Number);
      requireValid(
        !headerRanges.some(([a, b]) => low! <= b && a <= high!),
        'AWG header ranges must be disjoint'
      );
      headerRanges.push([low!, high!]);
    }
  if (iface.HeaderProtectionKey) {
    requireValid(
      validKey(iface.HeaderProtectionKey),
      'Invalid header protection key encoding'
    );
    if (Buffer.from(iface.HeaderProtectionKey, 'base64').some((b) => b !== 0))
      requireValid(
        ['S1', 'S2', 'S3', 'S4'].every((key) => Number(iface[key] ?? 0) >= 12),
        'Header protection requires every S1-S4 to be at least 12'
      );
  }
  for (const key of ['RandomTrailers', 'DisableCookies'])
    if (iface[key])
      requireValid(/^(0|1|on|off)$/.test(iface[key]), 'Invalid AWG boolean');
  for (const key of [
    'ContentPaddingAddition',
    'RekeyAfterTime',
    'RekeyTimeout',
    'RejectAfterTime',
    'KeepaliveTimeout',
    'MaxHandshakeAttempts',
  ]) {
    if (iface[key])
      requireValid(range(iface[key], 65535), 'Invalid AWG uint16 range');
  }
  for (const key of [
    'RekeyAfterTime',
    'RekeyTimeout',
    'RejectAfterTime',
    'KeepaliveTimeout',
    'MaxHandshakeAttempts',
  ])
    if (iface[key]) {
      const [low, high = low] = iface[key]!.split('-').map(Number);
      requireValid(
        high === 0 || low! > 0,
        'Timer range must start above zero or use 0 to disable'
      );
    }
  if (
    iface.RejectAfterTime &&
    Number(iface.RejectAfterTime.split('-').at(-1)) > 0
  ) {
    const reject = Number(iface.RejectAfterTime.split('-')[0]);
    for (const key of ['RekeyAfterTime', 'RekeyTimeout', 'KeepaliveTimeout'])
      if (iface[key]) {
        const values = iface[key]!.split('-').map(Number);
        const high = values[values.length - 1]!;
        requireValid(
          high === 0 || high < reject,
          'Rekey and keepalive timers must precede RejectAfterTime'
        );
      }
  }
  for (const key of ['I1', 'I2', 'I3', 'I4', 'I5'])
    if (iface[key]) {
      const size = cpsPacketSize(iface[key]!);
      requireValid(
        size !== null && size <= mtu,
        'Invalid CPS packet or packet larger than outbound MTU'
      );
    }
  if (iface.DNS)
    requireValid(
      iface.DNS.split(',').every((value) => isIPv4(value.trim())),
      'DNS metadata must contain IPv4 addresses'
    );
  return { address, mtu, interface: iface, peer };
}

export function egressInterface(id: string): string {
  return `awe${createHash('sha256').update(id).digest('hex').slice(0, 8)}`;
}

export function renderAwgProfile(profile: ImportedAwgProfile): string {
  // Client DNS stays in the stored import, but never invokes resolvconf here.
  const iface: Record<string, string> = {
    ...profile.interface,
    Table: 'off',
    MTU: String(profile.mtu),
  };
  delete iface.DNS;
  return (
    '[Interface]\n' +
    Object.entries(iface)
      .map(([k, v]) => `${k} = ${v}`)
      .join('\n') +
    '\n\n[Peer]\n' +
    Object.entries(profile.peer)
      .map(([k, v]) => `${k} = ${v}`)
      .join('\n') +
    '\n'
  );
}

export function validateRoutingConfig(
  value: unknown,
  context?: RoutingContext
): RoutingConfig {
  const result = RoutingConfigSchema.safeParse(value);
  requireValid(
    result.success,
    'Invalid routing configuration; check rules and outbound fields'
  );
  const config = result.data;
  const keys = new Set(context?.inboundPrivateKeys ?? []);
  const addresses: string[] = [];
  const listenPorts = new Set(
    context?.inboundPort ? [context.inboundPort] : []
  );
  if (context) {
    requireValid(
      /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/.test(context.inboundInterface),
      'Invalid inbound interface'
    );
    ipv4Cidr(context.sourceCidr);
    requireValid(
      !overlaps(context.sourceCidr, '10.0.0.0/8'),
      'Inbound routing subnet must not overlap 10.0.0.0/8'
    );
  }
  for (const egress of config.egresses) {
    const imported = parseAwgProfile(egress.profile);
    requireValid(
      !keys.has(imported.interface.PrivateKey!),
      'Outbound must use an independently allocated peer key'
    );
    keys.add(imported.interface.PrivateKey!);
    requireValid(
      !addresses.some((address) => overlaps(address, imported.address)) &&
        (!context || !overlaps(context.sourceCidr, imported.address)),
      'Outbound address overlaps an inbound or another outbound'
    );
    addresses.push(imported.address);
    const port = Number(imported.interface.ListenPort ?? 0);
    requireValid(
      !port || !listenPorts.has(port),
      'Outbound ListenPort overlaps another local AWG interface'
    );
    if (port) listenPorts.add(port);
  }
  const ruleSets = new Map<string, string>();
  for (const rule of config.rules) {
    for (const cidr of rule.cidrs) ipv4Cidr(cidr);
    for (const set of rule.ruleSets) {
      const previous = ruleSets.get(set.tag);
      requireValid(
        !previous || previous === `${set.url}|${set.format}`,
        'Rule set tag has conflicting definitions'
      );
      const host = new URL(set.url).hostname;
      requireValid(
        host !== 'localhost' &&
          (!isIPv4(host) ||
            !['0.', '10.', '127.', '169.254.', '192.168.'].some((prefix) =>
              host.startsWith(prefix)
            )) &&
          !host.includes(':'),
        'Rule set URLs must not target local networks'
      );
      ruleSets.set(set.tag, `${set.url}|${set.format}`);
    }
  }
  requireValid(
    !config.enabled || config.rules.some((rule) => rule.enabled),
    'Enabled routing needs at least one enabled rule'
  );
  return config;
}
