import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import { migrate } from 'drizzle-orm/libsql/migrator';
import { eq } from 'drizzle-orm';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import * as schema from '../../server/database/schema';
import { ClientService } from '../../server/database/repositories/client/service';
import {
  ClientEditableUpdateError,
  ClientUpdateSchema,
} from '../../server/database/repositories/client/types';
import { roles } from '../../shared/utils/permissions';

vi.mock('#server/utils/Database', () => ({ default: {} }));
vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: '51821' },
}));
vi.mock('#server/utils/cmd', () => ({
  exec: vi.fn(() => {
    throw new Error('Client database tests must not execute commands');
  }),
}));

let sql: ReturnType<typeof createClient>;
let directory: string;
let clients: ClientService;

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'awg-client-mutation-'));
  sql = createClient({ url: `file:${join(directory, 'test.sqlite')}` });
  const db = drizzle({ client: sql, schema });
  await migrate(db, { migrationsFolder: './server/database/migrations' });
  await db.insert(schema.user).values({
    id: 1,
    username: 'fixture-admin',
    name: 'Fixture administrator',
    role: roles.ADMIN,
    enabled: true,
    totpVerified: false,
  });
  await db
    .update(schema.wgInterface)
    .set({
      ipv4Cidr: '172.31.80.0/24',
      ipv6Cidr: 'fd31:80::/64',
      mtu: 1340,
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
      awgSettings: {
        headerProtectionKey: Buffer.alloc(32, 1).toString('base64'),
        randomTrailers: true,
      },
    })
    .where(eq(schema.wgInterface.name, 'wg0'));
  await db.insert(schema.client).values({
    id: 21,
    userId: 1,
    interfaceId: 'wg0',
    name: 'Original',
    ipv4Address: '172.31.80.2',
    ipv6Address: 'fd31:80::2',
    privateKey: 'fixture-private-key',
    publicKey: 'fixture-public-key',
    preSharedKey: '',
    preUp: 'fixture-existing-hook',
    enabled: true,
    expiresAt: null,
    allowedIps: ['0.0.0.0/0'],
    dns: ['192.0.2.53'],
    serverAllowedIps: [],
    mtu: 1340,
    persistentKeepalive: 0,
    jC: 4,
    jMin: 59,
    jMax: 202,
    i1: '<b 0xc000000001><r 8>',
    awgSettings: { contentPaddingAddition: '15-53' },
  });
  clients = new ClientService(db);
});
afterEach(async () => {
  sql?.close();
  await rm(directory, { recursive: true, force: true });
});

describe('atomic editable client updates', () => {
  test('concurrent disjoint patches preserve both edits and existing cryptographic/network fields', async () => {
    const original = await clients.get(21);
    await Promise.all([
      clients.updateEditableFields(21, { name: 'Renamed' }),
      clients.updateEditableFields(21, { dns: ['198.51.100.53'] }),
    ]);
    expect(await clients.get(21)).toMatchObject({
      name: 'Renamed',
      dns: ['198.51.100.53'],
      privateKey: original!.privateKey,
      publicKey: original!.publicKey,
      preSharedKey: '',
      ipv4Address: original!.ipv4Address,
      ipv6Address: original!.ipv6Address,
      preUp: original!.preUp,
      jC: original!.jC,
      i1: original!.i1,
      awgSettings: original!.awgSettings,
    });
  });
  test('a queued legacy edit to hooks and AWG tuning is not overwritten by a sparse API patch', async () => {
    const original = (await clients.get(21))!;
    const legacy = ClientUpdateSchema.parse({
      ...original,
      preUp: 'fixture-changed-legacy-hook',
      jC: 5,
      i1: '<b ff><r 12>',
      awgSettings: { contentPaddingAddition: '3-7' },
    });
    await Promise.all([
      clients.update(21, legacy),
      clients.updateEditableFields(21, { name: 'Renamed' }),
    ]);
    expect(await clients.get(21)).toMatchObject({
      name: 'Renamed',
      preUp: legacy.preUp,
      jC: 5,
      i1: legacy.i1,
      awgSettings: legacy.awgSettings,
      privateKey: original.privateKey,
      preSharedKey: '',
      ipv4Address: original.ipv4Address,
    });
  });
  test('enabling checks the fresh expiration written by a preceding legacy request', async () => {
    const stale = (await clients.get(21))!;
    const previous = clients.update(
      21,
      ClientUpdateSchema.parse({
        ...stale,
        enabled: false,
        expiresAt: '2001-01-01T00:00:00Z',
      })
    );
    const attemptedEnable = clients.updateEditableFields(21, { enabled: true });
    const failure = expect(attemptedEnable).rejects.toMatchObject({
      statusCode: 422,
    });
    await previous;
    await failure;
    expect(await clients.get(21)).toMatchObject({
      enabled: false,
      expiresAt: '2001-01-01T00:00:00Z',
      privateKey: stale.privateKey,
    });
  });
  test('a deleted client returns typed 404 and failed validation does not poison the queue', async () => {
    await expect(
      clients.updateEditableFields(21, { mtu: 9001 })
    ).rejects.toThrow();
    await clients.updateEditableFields(21, { name: 'After failed validation' });
    const deleted = clients.delete(21);
    const patch = clients.updateEditableFields(21, { name: 'Not recreated' });
    const failure = expect(patch).rejects.toBeInstanceOf(
      ClientEditableUpdateError
    );
    await deleted;
    await failure;
    expect(await clients.get(21)).toBeUndefined();
  });
  test('the service itself rejects secret or hook fields even when called without the HTTP validator', async () => {
    const original = await clients.get(21);
    for (const patch of [
      { name: 'Changed', privateKey: 'replacement' },
      { postUp: 'replacement' },
      {},
    ])
      expect(() => clients.updateEditableFields(21, patch as never)).toThrow(
        'Unsupported editable client fields'
      );
    expect(await clients.get(21)).toEqual(original);
  });
});
