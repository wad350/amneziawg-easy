import { readFileSync } from 'node:fs';

import { createClient } from '@libsql/client';
import { describe, expect, test, vi } from 'vitest';

import type { InterfaceType } from '../../server/database/repositories/interface/types';
import type { ClientType } from '../../server/database/repositories/client/types';
import type { UserConfigType } from '../../server/database/repositories/userConfig/types';
import type { HooksType } from '../../server/database/repositories/hooks/types';
import type { AwgParameters } from '../../shared/types/amneziawg';

import { parseWgDump, wg } from '#server/utils/wgHelper';
import {
  AwgParametersSchema,
  AwgClientSettingsSchema,
  AwgSettingsSchema,
  cpsPacketSize,
  generateAwg31Parameters,
  parseAwgRange,
  resolveClientAwgSettings,
  serializeAwgParameters,
  stripClientAwgSharedSettings,
} from '#server/utils/amneziawg';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: '51821' },
}));
vi.mock('#server/utils/cmd', () => ({
  exec: vi.fn(() => {
    throw new Error('No command should run in config tests');
  }),
}));

const legacy: AwgParameters = {
  jC: 7,
  jMin: 10,
  jMax: 1000,
  s1: 128,
  s2: 56,
  s3: null,
  s4: null,
  h1: '100',
  h2: '200',
  h3: '300',
  h4: '400',
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
  awgSettings: null,
};

const iface = {
  ...legacy,
  name: 'wg0',
  device: 'eth0',
  port: 47822,
  privateKey: 'server-private',
  publicKey: 'server-public',
  ipv4Cidr: '172.30.61.0/24',
  ipv6Cidr: 'fdcc:ad94:bacf:61a4::/64',
  mtu: 1340,
  routingTable: 'auto',
  enabled: true,
  firewallEnabled: false,
  createdAt: '2026-10-07',
  updatedAt: '2026-10-07',
} satisfies InterfaceType;

const client = {
  id: 1,
  userId: 1,
  interfaceId: 'wg0',
  name: 'Laptop',
  ipv4Address: '172.30.61.2',
  ipv6Address: 'fdcc:ad94:bacf:61a4::2',
  privateKey: 'client-private',
  publicKey: 'client-public',
  preSharedKey: 'client-psk',
  preUp: '',
  postUp: '',
  preDown: '',
  postDown: '',
  expiresAt: null,
  allowedIps: null,
  serverAllowedIps: [],
  firewallIps: null,
  persistentKeepalive: 25,
  mtu: 1340,
  jC: 7,
  jMin: 10,
  jMax: 1000,
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
  awgSettings: null,
  dns: null,
  serverEndpoint: null,
  enabled: true,
  createdAt: '2026-10-07',
  updatedAt: '2026-10-07',
} satisfies ClientType;

const userConfig = {
  defaultDns: ['1.1.1.1'],
  defaultAllowedIps: ['0.0.0.0/0'],
  host: '192.0.2.1',
  port: 47822,
} as UserConfigType;

describe('AWG3.1 validation and preview', () => {
  test('generates compatible preview parameters without modifying supplied state', () => {
    const original = JSON.stringify({ iface, client });
    const keys = new Set<string>();
    for (let i = 0; i < 32; i++) {
      const preview = generateAwg31Parameters();
      expect(AwgParametersSchema.safeParse(preview).success).toBe(true);
      expect(preview).toMatchObject({
        h1: '1',
        h2: '2',
        h3: '3',
        h4: '4',
        i1: null,
        i5: null,
      });
      expect(
        Buffer.from(preview.awgSettings!.headerProtectionKey!, 'base64')
      ).toHaveLength(32);
      keys.add(preview.awgSettings!.headerProtectionKey!);
      const config = wg.generateClientConfig(
        { ...iface, ...preview },
        userConfig,
        client,
        { enableIpv6: false }
      );
      expect(config).toContain('HeaderProtectionKey = ');
      expect(config).toContain('DisableCookies = 0');
      expect(Buffer.byteLength(config)).toBeLessThan(1800);
    }
    expect(keys.size).toBe(32);
    expect(JSON.stringify({ iface, client })).toBe(original);
  });

  test('enforces actual tools integer sizes, ordered ranges and integer padding', () => {
    expect(parseAwgRange('65535')).toEqual({ low: 65535, high: 65535 });
    expect(parseAwgRange('65536')).toBeNull();
    expect(
      AwgSettingsSchema.safeParse({ rekeyAfterTime: '65536' }).success
    ).toBe(false);
    expect(
      AwgSettingsSchema.safeParse({ contentPaddingAddition: '20-10' }).success
    ).toBe(false);
    expect(
      AwgParametersSchema.safeParse({ ...legacy, h1: '2147483648-4294967295' })
        .success
    ).toBe(true);
    expect(AwgParametersSchema.safeParse({ ...legacy, s1: -1 }).success).toBe(
      false
    );
    expect(AwgParametersSchema.safeParse({ ...legacy, jC: 1.5 }).success).toBe(
      false
    );
    expect(
      AwgParametersSchema.safeParse({ ...legacy, jMin: 1001 }).success
    ).toBe(false);
    expect(AwgSettingsSchema.safeParse({ rekeyTimeout: '0-5' }).success).toBe(
      false
    );
  });

  test('rejects overlapping headers, unsafe Header Protection and timer ordering', () => {
    const preview = generateAwg31Parameters();
    expect(
      AwgParametersSchema.safeParse({ ...preview, h2: '1-2' }).success
    ).toBe(false);
    expect(AwgParametersSchema.safeParse({ ...preview, s4: 11 }).success).toBe(
      false
    );
    expect(
      AwgSettingsSchema.safeParse({ headerProtectionKey: 'bad-key' }).success
    ).toBe(false);
    expect(
      AwgSettingsSchema.safeParse({
        rekeyAfterTime: '90-180',
        rejectAfterTime: '150-240',
      }).success
    ).toBe(false);
    expect(
      AwgSettingsSchema.safeParse({ command: 'echo unsafe' }).success
    ).toBe(false);
  });

  test('accepts portable upstream CPS grammar and rejects config injection or oversized packets', () => {
    expect(cpsPacketSize('<b 0xc000000001><rc 8><t><r 50><rd 5>')).toBe(72);
    expect(cpsPacketSize('<b ff><t><t><r 1001>')).toBe(1010);
    expect(cpsPacketSize('')).toBe(0);
    for (const value of [
      '<r -1>',
      '<r 65508>',
      '<b 0xa>',
      '<unknown 1>',
      'junk<b 0xff>',
      '<b 0xff>\nPostUp = touch /tmp/pwned',
    ]) {
      expect(cpsPacketSize(value)).toBeNull();
      expect(
        AwgParametersSchema.safeParse({ ...legacy, i1: value }).success
      ).toBe(false);
    }
  });
});

describe('config compatibility and inheritance', () => {
  test('retains explicit zero and disabled flags, omitting only absent values', () => {
    const lines = serializeAwgParameters({
      ...legacy,
      jC: 0,
      s1: 0,
      awgSettings: {
        contentPaddingAddition: '0',
        randomTrailers: false,
        disableCookies: false,
      },
    });
    expect(lines).toContain('Jc = 0');
    expect(lines).toContain('S1 = 0');
    expect(lines).toContain('ContentPaddingAddition = 0');
    expect(lines).toContain('RandomTrailers = 0');
    expect(lines).toContain('DisableCookies = 0');
    expect(lines.some((line) => line.startsWith('I1 ='))).toBe(false);
  });

  test('keeps legacy exports byte-for-byte when advanced settings are null', () => {
    expect(
      wg.generateClientConfig(iface, userConfig, client, { enableIpv6: false })
    ).toBe(`[Interface]
PrivateKey = client-private
Address = 172.30.61.2/32
MTU = 1340
DNS = 1.1.1.1
Jc = 7
Jmin = 10
Jmax = 1000
S1 = 128
S2 = 56
H1 = 100
H2 = 200
H3 = 300
H4 = 400

[Peer]
PublicKey = server-public
PresharedKey = client-psk
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
Endpoint = 192.0.2.1:47822`);
    const hooks = {
      preUp: '',
      postUp: '',
      preDown: '',
      postDown: '',
    } as HooksType;
    const server = wg.generateServerInterface(iface, hooks, {
      enableIpv6: false,
    });
    expect(server).not.toContain('HeaderProtectionKey');
    expect(server).not.toContain('RandomTrailers');
    expect(server).toContain(
      'PrivateKey = server-private\nAddress = 172.30.61.1/24'
    );
  });

  test('exports peers without a PSK by omitting the directive in both configs', () => {
    const withoutPsk = { ...client, preSharedKey: '' };
    expect(wg.generateServerPeer(withoutPsk, { enableIpv6: false }))
      .toBe(`# Client: Laptop (1)
[Peer]
PublicKey = client-public
AllowedIPs = 172.30.61.2/32`);
    const exported = wg.generateClientConfig(iface, userConfig, withoutPsk, {
      enableIpv6: false,
    });
    expect(exported).not.toContain('PresharedKey');
    expect(exported).toBe(
      wg
        .generateClientConfig(iface, userConfig, client, { enableIpv6: false })
        .replace('PresharedKey = client-psk\n', '')
    );
  });

  test.each(['client-psk', Buffer.alloc(32).toString('base64')])(
    'retains a nonempty PSK unchanged in server and client exports: %s',
    (preSharedKey) => {
      const withPsk = { ...client, preSharedKey };
      expect(wg.generateServerPeer(withPsk, { enableIpv6: false }))
        .toBe(`# Client: Laptop (1)
[Peer]
PublicKey = client-public
PresharedKey = ${preSharedKey}
AllowedIPs = 172.30.61.2/32`);
      expect(
        wg.generateClientConfig(iface, userConfig, withPsk, {
          enableIpv6: false,
        })
      ).toContain(
        `PublicKey = server-public\nPresharedKey = ${preSharedKey}\nAllowedIPs = 0.0.0.0/0`
      );
    }
  );

  test('allows peer timing overrides while preserving the shared header key', () => {
    const settings = generateAwg31Parameters().awgSettings!;
    const override = {
      contentPaddingAddition: '0',
      persistentKeepaliveRange: '20-30',
    };
    const merged = resolveClientAwgSettings(settings, override)!;
    expect(merged.headerProtectionKey).toBe(settings.headerProtectionKey);
    expect(merged.contentPaddingAddition).toBe('0');
    expect(merged.randomTrailers).toBe(settings.randomTrailers);
    expect(settings.contentPaddingAddition).toBe('0-31');
    expect(
      resolveClientAwgSettings(settings, {
        headerProtectionKey: Buffer.alloc(32, 1).toString('base64'),
        randomTrailers: false,
      })
    ).toMatchObject({
      headerProtectionKey: settings.headerProtectionKey,
      randomTrailers: settings.randomTrailers,
    });
    expect(AwgClientSettingsSchema.safeParse(override).success).toBe(true);
    expect(
      AwgClientSettingsSchema.safeParse({ randomTrailers: false }).success
    ).toBe(false);
    expect(
      AwgClientSettingsSchema.safeParse({
        headerProtectionKey: settings.headerProtectionKey,
      }).success
    ).toBe(false);
    expect(
      stripClientAwgSharedSettings({
        ...override,
        headerProtectionKey: settings.headerProtectionKey,
        randomTrailers: false,
      })
    ).toEqual(override);
    const preview = generateAwg31Parameters();
    const config = wg.generateClientConfig(
      { ...iface, ...preview },
      userConfig,
      { ...client, awgSettings: override }
    );
    expect(config).toContain('PersistentKeepalive = 20-30');
    expect(config).toContain('ContentPaddingAddition = 0');
  });

  test('parses unchanged peer columns after the longer AWG3.1 interface dump row', () => {
    const header = Array.from({ length: 29 }, (_, i) => `field${i}`).join('\t');
    const result = parseWgDump(
      `${header}\npublic\tpsk\t192.0.2.2:1234\t172.30.61.2/32\t123\t100\t200\t20-30\n`
    );
    expect(result).toEqual([
      {
        publicKey: 'public',
        preSharedKey: 'psk',
        endpoint: '192.0.2.2:1234',
        allowedIps: '172.30.61.2/32',
        latestHandshakeAt: new Date(123000),
        transferRx: 100,
        transferTx: 200,
        persistentKeepalive: '20-30',
      },
    ]);
    expect(() => parseWgDump(`${header}\nmalformed`)).toThrow();
  });
});

test('migration adds nullable settings without modifying existing keys or parameters', async () => {
  const db = createClient({ url: ':memory:' });
  try {
    await db.executeMultiple(`CREATE TABLE clients_table (id INTEGER PRIMARY KEY, private_key TEXT, j_c INTEGER);
      CREATE TABLE interfaces_table (name TEXT PRIMARY KEY, private_key TEXT, h1 TEXT);
      INSERT INTO clients_table VALUES (1, 'existing-client-private', 7);
      INSERT INTO interfaces_table VALUES ('wg0', 'existing-server-private', '100');`);
    const migration = readFileSync(
      new URL(
        '../../server/database/migrations/0008_awg31_settings.sql',
        import.meta.url
      ),
      'utf8'
    );
    await db.executeMultiple(
      migration.replaceAll('--> statement-breakpoint', '')
    );
    expect(
      (
        await db.execute(
          'SELECT private_key, j_c, awg_settings FROM clients_table'
        )
      ).rows[0]
    ).toMatchObject({
      private_key: 'existing-client-private',
      j_c: 7,
      awg_settings: null,
    });
    expect(
      (
        await db.execute(
          'SELECT private_key, h1, awg_settings FROM interfaces_table'
        )
      ).rows[0]
    ).toMatchObject({
      private_key: 'existing-server-private',
      h1: '100',
      awg_settings: null,
    });
  } finally {
    db.close();
  }
});
