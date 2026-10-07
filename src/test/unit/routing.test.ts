import {
  mkdtemp,
  readFile,
  stat,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, test } from 'vitest';

import { RoutingConfigSchema } from '../../shared/types/routing';
import {
  parseAwgProfile,
  renderAwgProfile,
  validateRoutingConfig,
  egressInterface,
} from '../../server/utils/routingConfig';
import {
  previewRouting,
  renderSingBox,
  renderNftables,
  renderRoutingGate,
  youtubeRuPreset,
} from '../../server/utils/routingRender';
import {
  loadRoutingConfig,
  saveRoutingConfig,
  loadAppliedRoutingConfig,
  saveAppliedRoutingConfig,
} from '../../server/utils/routingStore';
import {
  applyRouting,
  getRoutingStatus,
  stopRouting,
  startRouting,
  armAppliedRoutingGate,
} from '../../server/utils/routingRuntime';

const privateKey = Buffer.alloc(32, 1).toString('base64');
const publicKey = Buffer.alloc(32, 2).toString('base64');
const hpKey = Buffer.alloc(32, 3).toString('base64');
const profile = `[Interface]\nPrivateKey = ${privateKey}\nAddress = 172.31.90.2/32\nDNS = 77.88.8.8\nMTU = 1340\nJc = 7\nJmin = 10\nJmax = 100\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 0-1\nH2 = 2147483648-2147483650\nH3 = 3000000000\nH4 = 4294967295\nI1 = <b 0x010203><r 8><t>\nHeaderProtectionKey = ${hpKey}\nContentPaddingAddition = 10-30\nRekeyAfterTime = 100-120\nRekeyTimeout = 5-10\nRejectAfterTime = 150-180\nKeepaliveTimeout = 10-20\nMaxHandshakeAttempts = 10-20\nRandomTrailers = on\nDisableCookies = 0\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = 203.0.113.2:37462\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 20-30\n`;
const context = {
  inboundInterface: 'wg0',
  sourceCidr: '172.31.80.0/24',
  inboundPort: 51820,
};
const config = () =>
  RoutingConfigSchema.parse({
    enabled: true,
    egresses: [
      { id: 'remote', name: 'Remote', profile, independentPeer: true },
    ],
    rules: youtubeRuPreset('remote', {
      domains: ['openvpn.example.com'],
      cidrs: ['198.51.100.224/32'],
    }),
  });
const temporary: string[] = [];
afterEach(async () => {
  await stopRouting();
  await Promise.all(
    temporary.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))
  );
});

describe('AWG outbound imports', () => {
  test('preserves every supported 3.1 parameter and keepalive ranges', () => {
    const parsed = parseAwgProfile(profile);
    expect(parsed.interface.H4).toBe('4294967295');
    expect(parsed.interface.HeaderProtectionKey).toBe(hpKey);
    expect(parsed.interface.MaxHandshakeAttempts).toBe('10-20');
    expect(parsed.peer.PersistentKeepalive).toBe('20-30');
    const rendered = renderAwgProfile(parsed);
    expect(rendered).toContain('Table = off');
    expect(rendered).toContain('ContentPaddingAddition = 10-30');
    expect(rendered).toContain('RandomTrailers = on');
    expect(rendered).toContain(`HeaderProtectionKey = ${hpKey}`);
    expect(parsed.interface.DNS).toBe('77.88.8.8');
    expect(rendered).not.toContain('DNS =');
  });
  test('preserves a valid client /24 while rejecting an overlapping connected subnet', () => {
    const imported = profile.replace('172.31.90.2/32', '172.31.90.2/24');
    expect(parseAwgProfile(imported).address).toBe('172.31.90.2/24');
    expect(renderAwgProfile(parseAwgProfile(imported))).toContain(
      'Address = 172.31.90.2/24'
    );
    const candidate = config();
    candidate.egresses[0]!.profile = imported;
    expect(validateRoutingConfig(candidate, context).egresses).toHaveLength(1);
    expect(() =>
      validateRoutingConfig(candidate, {
        ...context,
        sourceCidr: '172.31.90.0/24',
      })
    ).toThrow();
  });
  test.each([
    'PostUp = touch /tmp/test',
    'PreDown = false',
    'Table = auto',
    'SaveConfig = true',
    'UnexpectedKey = value',
  ])('rejects unsafe imported setting %s', (line) => {
    expect(() =>
      parseAwgProfile(profile.replace('[Peer]', `${line}\n[Peer]`))
    ).toThrow();
  });
  test('rejects duplicate peers, duplicate fields and implicit DNS endpoint lookup', () => {
    expect(() =>
      parseAwgProfile(profile + '[Peer]\nPublicKey = bad')
    ).toThrow();
    expect(() =>
      parseAwgProfile(profile.replace('[Peer]', 'MTU = 1340\n[Peer]'))
    ).toThrow();
    expect(() =>
      parseAwgProfile(
        profile.replace('203.0.113.2:37462', 'remote.example.com:37462')
      )
    ).toThrow();
  });
  test('rejects uint16 truncation and header overlap', () => {
    expect(() =>
      parseAwgProfile(profile.replace('20-30\n', '20-70000\n'))
    ).toThrow();
    expect(() =>
      parseAwgProfile(profile.replace('H4 = 4294967295', 'H4 = 3000000000'))
    ).toThrow();
    expect(() =>
      parseAwgProfile(
        profile.replace(
          'ContentPaddingAddition = 10-30',
          'ContentPaddingAddition = 1-65536'
        )
      )
    ).toThrow();
  });
  test('rejects 10/8 address, low header-protection padding and malformed CPS', () => {
    expect(() =>
      parseAwgProfile(profile.replace('172.31.90.2/32', '10.5.0.2/32'))
    ).toThrow();
    expect(() =>
      parseAwgProfile(profile.replace('S4 = 12', 'S4 = 11'))
    ).toThrow();
    expect(() =>
      parseAwgProfile(profile.replace('<b 0x010203><r 8><t>', '<r 70000>'))
    ).toThrow();
  });
});

describe('routing validation and rendering', () => {
  test('routing starts disabled and empty', () => {
    expect(RoutingConfigSchema.parse({})).toEqual({
      version: 1,
      enabled: false,
      egresses: [],
      rules: [],
    });
  });
  test('rules preserve first-match order, scopes and original destination', () => {
    const rendered = renderSingBox(validateRoutingConfig(config(), context));
    expect(rendered.route.rules[0]).toMatchObject({
      action: 'sniff',
      sniffer: ['http', 'tls', 'quic'],
    });
    expect(rendered.route.rules[1]).toMatchObject({
      port: [443],
      network: ['tcp', 'udp'],
      outbound: 'remote',
    });
    expect(rendered.route.rules[2]).toMatchObject({
      domain: ['openvpn.example.com'],
      outbound: 'direct',
    });
    expect(rendered.route.rules[3]).toMatchObject({
      ip_cidr: ['198.51.100.224/32'],
      outbound: 'direct',
    });
    expect(rendered.route.rules[4]).toMatchObject({
      domain_suffix: ['ru', 'xn--p1ai'],
      outbound: 'remote',
    });
    expect(JSON.stringify(rendered)).not.toContain('override_address');
    expect(rendered.route.final).toBe('direct');
  });
  test('nft interception stays inside the new interface and subnet', () => {
    const rendered = renderNftables(config(), context);
    expect(rendered).toContain('iifname != "wg0" return');
    expect(rendered).toContain('ip saddr != 172.31.80.0/24 return');
    expect(rendered).toContain('tcp dport { 443 }');
    expect(rendered).toContain('udp dport { 443 }');
    expect(rendered).not.toContain('hook output');
    expect(rendered).not.toContain('flush ruleset');
  });
  test('transition gate blocks the union of old/new selected ports, never host output', () => {
    const next = config();
    next.rules[0]!.ports = ['8443'];
    const gate = renderRoutingGate(
      [
        { config: config(), context },
        { config: next, context },
      ],
      true
    );
    expect(gate).toContain('delete table ip awg_easy_gate');
    expect(gate).toContain('priority -151');
    expect(gate).toContain(
      'iifname "wg0" ip saddr 172.31.80.0/24 tcp dport { 443 } counter drop'
    );
    expect(gate).toContain(
      'iifname "wg0" ip saddr 172.31.80.0/24 udp dport { 8443 } counter drop'
    );
    expect(gate).not.toContain('hook output');
    expect(gate).not.toContain('flush ruleset');
  });
  test('rejects reused keys, overlapping addresses, invalid CIDRs and unsafe references', () => {
    expect(() =>
      validateRoutingConfig(config(), {
        ...context,
        inboundPrivateKeys: [privateKey],
      })
    ).toThrow();
    expect(() =>
      validateRoutingConfig(config(), {
        ...context,
        sourceCidr: '172.31.90.0/24',
      })
    ).toThrow();
    expect(() =>
      validateRoutingConfig(config(), { ...context, sourceCidr: '10.0.0.0/8' })
    ).toThrow();
    const candidate = config();
    candidate.rules[0]!.cidrs.push('1.1.1.1/99');
    expect(() => validateRoutingConfig(candidate, context)).toThrow();
    candidate.rules[0]!.cidrs = [];
    candidate.rules[0]!.outbound = 'missing';
    expect(() => validateRoutingConfig(candidate, context)).toThrow();
  });
  test('remote rule sets allow trusted HTTPS publishers without local file paths', () => {
    const candidate = config();
    candidate.rules[0]!.ruleSets = [
      {
        tag: 'youtube',
        url: 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.srs',
        format: 'binary',
      },
    ];
    expect(
      validateRoutingConfig(candidate, context).rules[0]!.ruleSets
    ).toHaveLength(1);
    candidate.rules[0]!.ruleSets[0]!.url = 'https://127.0.0.1/secret';
    expect(() => validateRoutingConfig(candidate, context)).toThrow();
    candidate.rules[0]!.ruleSets[0]!.url = 'file:///etc/passwd';
    expect(() => validateRoutingConfig(candidate, context)).toThrow();
  });
  test('pure preview exposes no private or preshared keys and starts no processes', () => {
    const result = previewRouting(config(), context);
    expect(result.valid).toBe(true);
    expect(JSON.stringify(result)).not.toContain(privateKey);
    expect(JSON.stringify(result)).not.toContain(hpKey);
    expect(getRoutingStatus().state).toBe('stopped');
    expect(egressInterface('remote')).toMatch(/^awe[a-f0-9]{8}$/);
  });
  test('private debug diagnostics require an explicit runtime render option', () => {
    expect(renderSingBox(config()).log.level).toBe('warn');
    expect(renderSingBox(config(), { debug: true }).log.level).toBe('debug');
    expect(previewRouting(config(), context).singBox.log.level).toBe('warn');
    expect(
      JSON.stringify(renderSingBox(config(), { debug: true }))
    ).not.toContain(privateKey);
  });
  test('enabled apply refuses this developer environment before runtime writes', async () => {
    await expect(applyRouting(config(), context)).rejects.toThrow('isolated');
    expect(getRoutingStatus().state).toBe('stopped');
  });
});

describe('private routing storage', () => {
  test('enabled draft never starts at reboot; only explicitly applied config is loaded', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'routing-unit-'));
    temporary.push(dir);
    const draft = join(dir, 'draft.json');
    const applied = join(dir, 'applied.json');
    await saveRoutingConfig(config(), draft);
    expect((await loadRoutingConfig(draft)).enabled).toBe(true);
    expect((await loadAppliedRoutingConfig(applied)).enabled).toBe(false);
    expect((await startRouting(context, applied)).state).toBe('stopped');
    await saveAppliedRoutingConfig(RoutingConfigSchema.parse({}), applied);
    expect((await startRouting(context, applied)).enabled).toBe(false);
    expect((await loadRoutingConfig(draft)).enabled).toBe(true);
  });
  test('startup gate ignores an enabled draft and arms only explicitly applied policy', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'routing-unit-'));
    temporary.push(dir);
    const draft = join(dir, 'draft.json');
    const applied = join(dir, 'applied.json');
    await saveRoutingConfig(config(), draft);
    expect((await armAppliedRoutingGate(context, applied)).enabled).toBe(false);
    await saveAppliedRoutingConfig(RoutingConfigSchema.parse({}), applied);
    expect((await armAppliedRoutingGate(context, applied)).enabled).toBe(false);
    await saveAppliedRoutingConfig(config(), applied);
    await expect(armAppliedRoutingGate(context, applied)).rejects.toThrow(
      'isolated'
    );
    expect((await loadAppliedRoutingConfig(applied)).enabled).toBe(true);
    expect(getRoutingStatus().state).toBe('stopped');
    await stopRouting({ preserveGate: true });
    expect(getRoutingStatus().enabled).toBe(false);
  });
  test('atomic mode 0600 storage roundtrips and absent config is disabled', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'routing-unit-'));
    temporary.push(dir);
    const path = join(dir, 'routing.json');
    expect((await loadRoutingConfig(path)).enabled).toBe(false);
    await saveRoutingConfig(config(), path);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(await loadRoutingConfig(path)).toEqual(config());
    expect(JSON.parse(await readFile(path, 'utf8')).version).toBe(1);
  });
  test('rejects symlinks and publicly readable files', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'routing-unit-'));
    temporary.push(dir);
    const target = join(dir, 'target');
    await writeFile(target, JSON.stringify(config()), { mode: 0o644 });
    const path = join(dir, 'routing.json');
    await symlink(target, path);
    await expect(loadRoutingConfig(path)).rejects.toThrow('owner-only');
    await expect(loadRoutingConfig(target)).rejects.toThrow('owner-only');
  });
});
