import { describe, expect, test } from 'vitest';

import { resolveAppPath } from '../../shared/utils/appPath';

describe('raw browser URLs under the application base', () => {
  test('preserves root deployment and query strings', () => {
    expect(resolveAppPath('/', '/api/client/12/configuration')).toBe(
      '/api/client/12/configuration'
    );
    expect(resolveAppPath('/', '/api/auth/github?link=true')).toBe(
      '/api/auth/github?link=true'
    );
    expect(resolveAppPath('/', './cnf/token')).toBe('/cnf/token');
    expect(resolveAppPath('/', '/')).toBe('/');
  });

  test('resolves nested deployment paths consistently', () => {
    expect(resolveAppPath('/private/panel/', '/api/client/12/qrcode.svg')).toBe(
      '/private/panel/api/client/12/qrcode.svg'
    );
    expect(resolveAppPath('/private/panel', 'logo.png')).toBe(
      '/private/panel/logo.png'
    );
    expect(resolveAppPath('/private/panel/', './cnf/token')).toBe(
      '/private/panel/cnf/token'
    );
    expect(resolveAppPath('/private/panel/', '/')).toBe('/private/panel/');
  });

  test('does not duplicate a base or confuse adjacent names', () => {
    expect(resolveAppPath('/panel/', '/panel/api/client?sort=asc')).toBe(
      '/panel/api/client?sort=asc'
    );
    expect(resolveAppPath('/panel/', '/panel?tab=clients')).toBe(
      '/panel?tab=clients'
    );
    expect(resolveAppPath('/panel/', '/panel')).toBe('/panel');
    expect(resolveAppPath('/panel/', '/panel-other')).toBe(
      '/panel/panel-other'
    );
  });

  test.each([
    'https://example.com/releases',
    '//example.com/avatar.png',
    'mailto:admin@example.com',
    'blob:https://example.com/opaque',
    'data:image/png;base64,AA==',
    '#svg-gradient',
  ])('preserves complete external or fragment URL %s', (url) => {
    expect(resolveAppPath('/panel/', url)).toBe(url);
  });
});
