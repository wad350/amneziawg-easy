import { readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import { integrationOpenApi } from '../../server/utils/integrationOpenApi';
import { isApiTokenOperationAllowed } from '../../server/utils/apiToken';

describe('versioned integration contract', () => {
  test('publishes the mounted API URL without changing its operation paths', () => {
    const nested = integrationOpenApi('/private/panel/');
    expect(nested.servers).toEqual([{ url: '/private/panel/api/v1' }]);
    expect(nested.paths).toEqual(integrationOpenApi().paths);
  });

  test('describes every v1 handler and matches the service-token allowlist', async () => {
    const root = fileURLToPath(
      new URL('../../server/api/v1/', import.meta.url)
    );
    const files = await readdir(root, { recursive: true });
    const handlers = files
      .filter((file) => /\.(get|post|patch|put|delete)\.ts$/.test(file))
      .map((file) => {
        const match = file.match(/^(.*)\.(get|post|patch|put|delete)\.ts$/)!;
        return {
          method: match[2]!,
          path:
            '/' +
            match[1]!
              .replace(/(^|\/)index$/, '')
              .replace(/\[([^\]]+)\]/g, '{$1}'),
        };
      });
    const contract = integrationOpenApi();
    const documented = Object.entries(contract.paths).flatMap(([path, item]) =>
      Object.keys(item)
        .filter((method) => method !== 'parameters')
        .map((method) => ({ path, method }))
    );
    expect(documented).toHaveLength(handlers.length);
    expect(documented).toEqual(expect.arrayContaining(handlers));
    for (const { path, method } of documented)
      expect(
        isApiTokenOperationAllowed(
          method,
          '/api/v1' + path.replace('{clientId}', '1')
        )
      ).toBe(true);
  });

  test('uses actual request defaults and excludes forbidden credential inputs', () => {
    const { schemas } = integrationOpenApi().components;
    expect(schemas.ClientCreate.required).toEqual(['name']);
    expect(schemas.ClientCreate.properties?.expiresAt?.default).toBeNull();
    expect(schemas.ClientPatch.additionalProperties).toBe(false);
    expect(Object.keys(schemas.ClientPatch.properties ?? {}).sort()).toEqual(
      [
        'name',
        'enabled',
        'expiresAt',
        'dns',
        'allowedIps',
        'mtu',
        'persistentKeepalive',
      ].sort()
    );
    const settings = JSON.stringify(
      schemas.ClientCreate.properties?.awgSettings
    );
    expect(settings).not.toContain('headerProtectionKey');
    expect(settings).not.toContain('randomTrailers');
    expect(settings).toContain('contentPaddingAddition');
    expect(schemas.RoutingRulesUpdate.required).toEqual(['revision', 'rules']);
    expect(schemas.RoutingRulesUpdate.properties?.apply?.default).toBe(false);
  });

  test('exports raw text and SVG and keeps secrets out of metadata schemas', () => {
    const document = integrationOpenApi();
    expect(document.openapi).toBe('3.1.0');
    expect(document.servers).toEqual([{ url: '/api/v1' }]);
    expect(
      document.paths['/clients/{clientId}/configuration'].get.responses['200']
        ?.content
    ).toHaveProperty('text/plain');
    expect(
      document.paths['/clients/{clientId}/qrcode.svg'].get.responses['200']
        ?.content
    ).toHaveProperty('image/svg+xml');
    expect(document.paths['/clients'].post.responses).toHaveProperty('201');
    expect(document.paths['/routing/rules'].put.responses).toHaveProperty(
      '409'
    );
    const metadata = JSON.stringify([
      document.components.schemas.Client,
      document.components.schemas.Server,
      document.components.schemas.Routing,
      document.components.schemas.PublicAwgSettings,
    ]);
    for (const key of [
      'privateKey',
      'preSharedKey',
      'headerProtectionKey',
      'oneTimeLink',
      'profile',
    ])
      expect(metadata).not.toContain(key);
  });
});
