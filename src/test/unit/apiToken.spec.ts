import { createHash } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { H3Event } from 'h3';

import {
  ApiTokenError,
  authenticateApiToken,
  isApiBearerAuthorization,
  isApiTokenOperationAllowed,
} from '../../server/utils/apiToken';
import { getCurrentUser } from '../../server/utils/session';

const auth = vi.hoisted(() => ({
  getByUsername: vi.fn(),
  getUser: vi.fn(),
  getSessionConfig: vi.fn(),
  getHeader: vi.fn(),
  getRequestURL: vi.fn(),
  getSession: vi.fn(),
  useSession: vi.fn(),
  baseURL: '/',
  isPasswordValid: vi.fn(),
  env: { INSECURE: false, DISABLE_PASSWORD_AUTH: false },
}));

vi.mock('#server/utils/Database', () => ({
  default: {
    users: { get: auth.getUser, getByUsername: auth.getByUsername },
    general: { getSessionConfig: auth.getSessionConfig },
  },
}));
vi.mock('#server/utils/config', () => ({ WG_ENV: auth.env }));
vi.mock('#server/utils/password', () => ({
  isPasswordValid: auth.isPasswordValid,
}));
vi.mock('nitropack/runtime', () => ({
  useRuntimeConfig: () => ({ app: { baseURL: auth.baseURL } }),
}));
vi.mock('h3', () => ({
  createError: (value: { statusCode: number; statusMessage: string }) =>
    Object.assign(new Error(value.statusMessage), value),
  getHeader: auth.getHeader,
  getRequestURL: auth.getRequestURL,
  getSession: auth.getSession,
  useSession: auth.useSession,
}));

const token = `awg_${Buffer.alloc(32).toString('base64url')}`;
const otherToken = `awg_${Buffer.alloc(32, 1).toString('base64url')}`;
const digest = createHash('sha256').update(token).digest('hex');
const config = { sha256: digest, username: 'integration' };
const user = {
  id: 42,
  username: 'integration',
  role: 2,
  enabled: true,
  totpVerified: false,
  password: 'test-only-hash',
};
const request = {
  authorization: `Bearer ${token}`,
  method: 'GET',
  path: '/api/v1/clients',
};

describe('integration API operation boundaries', () => {
  it.each([
    ['GET', '/api/v1/server'],
    ['GET', '/api/v1/openapi.json'],
    ['GET', '/api/v1/clients'],
    ['POST', '/api/v1/clients'],
    ['GET', '/api/v1/clients/1'],
    ['PATCH', '/api/v1/clients/17'],
    ['DELETE', '/api/v1/clients/17'],
    ['GET', '/api/v1/clients/17/configuration'],
    ['GET', '/api/v1/clients/17/qrcode.svg'],
    ['GET', '/api/v1/routing'],
    ['PUT', '/api/v1/routing/rules'],
  ])('allows the documented operation %s %s', (method, path) => {
    expect(isApiTokenOperationAllowed(method, path)).toBe(true);
  });

  it.each([
    ['GET', '/api/client'],
    ['GET', '/api/admin/interface'],
    ['POST', '/api/admin/hooks'],
    ['POST', '/api/me/password'],
    ['POST', '/api/me/totp'],
    ['POST', '/api/setup/2'],
    ['GET', '/api/v1/clients/0'],
    ['GET', '/api/v1/clients/01'],
    ['GET', '/api/v1/clients/-1'],
    ['GET', '/api/v1/clients/1.5'],
    ['GET', '/api/v1/clients/9007199254740992'],
    ['GET', '/api/v1/clients/%31'],
    ['GET', '/api/v1/clients/1/'],
    ['POST', '/api/v1/clients/1'],
    ['PUT', '/api/v1/clients/1'],
    ['PATCH', '/api/v1/clients/1/configuration'],
    ['DELETE', '/api/v1/clients/1/qrcode.svg'],
    ['POST', '/api/v1/routing/rules'],
    ['GET', '/api/v1/routing/rules'],
    ['PUT', '/api/v1/routing'],
  ])('rejects any other operation %s %s', (method, path) => {
    expect(isApiTokenOperationAllowed(method, path)).toBe(false);
  });
});

describe('opt-in API token authentication', () => {
  it('returns the current account without changing its role', async () => {
    const resolve = vi.fn().mockResolvedValue(user);
    await expect(authenticateApiToken(request, config, resolve)).resolves.toBe(
      user
    );
    expect(resolve).toHaveBeenCalledExactlyOnceWith('integration');
  });

  it('accepts a case-insensitive Bearer scheme and SHA256 hex digest', async () => {
    await expect(
      authenticateApiToken(
        { ...request, authorization: `bearer ${token}` },
        { ...config, sha256: digest.toUpperCase() },
        async () => user
      )
    ).resolves.toBe(user);
  });

  it.each([
    undefined,
    '',
    'Bearer',
    `Bearer${token}`,
    `Bearer  ${token}`,
    ` Bearer ${token}`,
    `Bearer ${token} `,
    `Bearer ${token}=`,
    `Bearer ${token.slice(0, -1)}`,
    `Bearer ${token.slice(0, -1)}B`,
    `Bearer ${token.toUpperCase()}`,
    `Bearer ${otherToken}`,
    `Basic ${token}`,
    `Bearer ${token}, Bearer ${token}`,
    [`Bearer ${token}`, `Bearer ${token}`],
    ['Basic test', `Bearer ${token}`],
  ])('rejects malformed, incorrect or duplicate credentials', async (value) => {
    const resolve = vi.fn().mockResolvedValue(user);
    await expect(
      authenticateApiToken(
        { ...request, authorization: value },
        config,
        resolve
      )
    ).rejects.toMatchObject({ statusCode: 401 });
    expect(resolve).not.toHaveBeenCalled();
  });

  it.each([
    { sha256: undefined, username: undefined },
    { sha256: undefined, username: 'integration' },
    { sha256: digest, username: undefined },
    { sha256: 'not-a-digest', username: 'integration' },
    { sha256: `${digest}00`, username: 'integration' },
    { sha256: digest, username: '' },
    { sha256: digest, username: ' integration' },
    { sha256: digest, username: 'integration\n' },
  ])('requires both valid configured credential fields', async (value) => {
    const resolve = vi.fn().mockResolvedValue(user);
    await expect(
      authenticateApiToken(request, value, resolve)
    ).rejects.toMatchObject({ statusCode: 401 });
    expect(resolve).not.toHaveBeenCalled();
  });

  it('does not resolve an account for operations outside the contract', async () => {
    const resolve = vi.fn().mockResolvedValue(user);
    await expect(
      authenticateApiToken(
        { ...request, method: 'POST', path: '/api/me/password' },
        config,
        resolve
      )
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(resolve).not.toHaveBeenCalled();
  });

  it('rejects a missing bound account', async () => {
    await expect(
      authenticateApiToken(request, config, async () => undefined)
    ).rejects.toMatchObject({ statusCode: 401 });
  });

  it('resolves enabled account state on every request', async () => {
    const resolve = vi
      .fn()
      .mockResolvedValueOnce(user)
      .mockResolvedValueOnce({ ...user, enabled: false });
    await expect(authenticateApiToken(request, config, resolve)).resolves.toBe(
      user
    );
    await expect(
      authenticateApiToken(request, config, resolve)
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it('does not bypass verified two-factor authentication', async () => {
    await expect(
      authenticateApiToken(request, config, async () => ({
        ...user,
        totpVerified: true,
      }))
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it('does not echo credentials or account identifiers into errors', async () => {
    try {
      await authenticateApiToken(
        { ...request, authorization: `Bearer ${otherToken}` },
        config,
        async () => user
      );
      expect.fail('Invalid token was accepted');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiTokenError);
      expect(String(error)).not.toContain(token);
      expect(String(error)).not.toContain(otherToken);
      expect(String(error)).not.toContain(digest);
      expect(String(error)).not.toContain(config.username);
    }
  });
});

describe('Bearer and existing session/Basic authentication precedence', () => {
  afterEach(() => vi.unstubAllEnvs());

  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    vi.stubEnv('AWG_API_TOKEN_SHA256', digest);
    vi.stubEnv('AWG_API_TOKEN_USER', config.username);
    auth.env.DISABLE_PASSWORD_AUTH = false;
    auth.baseURL = '/';
    auth.getHeader.mockReturnValue(undefined);
    auth.getRequestURL.mockReturnValue(
      new URL('https://example.com/api/v1/clients')
    );
    auth.getSessionConfig.mockResolvedValue({
      sessionPassword: 'test-session',
    });
    auth.getSession.mockResolvedValue({ data: {} });
    auth.getByUsername.mockResolvedValue(user);
    auth.getUser.mockResolvedValue(user);
    auth.isPasswordValid.mockResolvedValue(true);
  });

  const event = (rawHeaders: string[] = []) =>
    ({ node: { req: { rawHeaders } }, method: 'GET' }) as unknown as H3Event;

  it('detects malformed and merged Bearer attempts', () => {
    expect(isApiBearerAuthorization(undefined)).toBe(false);
    expect(isApiBearerAuthorization('Basic test')).toBe(false);
    expect(isApiBearerAuthorization(`Bearer${token}`)).toBe(true);
    expect(isApiBearerAuthorization(`Basic test, Bearer ${token}`)).toBe(true);
    expect(isApiBearerAuthorization(['Basic test', `Bearer ${token}`])).toBe(
      true
    );
  });

  it('does not fall back to a valid session for an invalid Bearer token', async () => {
    auth.getHeader.mockReturnValue(`Bearer ${otherToken}`);
    auth.getSession.mockResolvedValue({ data: { userId: user.id } });
    await expect(getCurrentUser(event())).rejects.toMatchObject({
      statusCode: 401,
    });
    expect(auth.getSessionConfig).not.toHaveBeenCalled();
    expect(auth.getUser).not.toHaveBeenCalled();
  });

  it('rejects duplicate raw Authorization headers before considering a session', async () => {
    auth.getHeader.mockReturnValue('Basic test');
    auth.getSession.mockResolvedValue({ data: { userId: user.id } });
    await expect(
      getCurrentUser(
        event([
          'Authorization',
          'Basic test',
          'authorization',
          `Bearer ${token}`,
        ])
      )
    ).rejects.toMatchObject({ statusCode: 401 });
    expect(auth.getSessionConfig).not.toHaveBeenCalled();
  });

  it('authenticates Bearer independently of password login and cookies', async () => {
    auth.getHeader.mockReturnValue(`Bearer ${token}`);
    auth.env.DISABLE_PASSWORD_AUTH = true;
    auth.getSession.mockResolvedValue({ data: { userId: 999 } });
    await expect(getCurrentUser(event())).resolves.toBe(user);
    expect(auth.getByUsername).toHaveBeenCalledExactlyOnceWith('integration');
    expect(auth.getSessionConfig).not.toHaveBeenCalled();
    expect(auth.isPasswordValid).not.toHaveBeenCalled();
  });

  it('authenticates the same integration token at a mounted API path', async () => {
    auth.baseURL = '/private/panel/';
    auth.getHeader.mockReturnValue(`Bearer ${token}`);
    auth.getRequestURL.mockReturnValue(
      new URL('https://example.com/private/panel/api/v1/clients')
    );
    await expect(getCurrentUser(event())).resolves.toBe(user);
    expect(auth.getSessionConfig).not.toHaveBeenCalled();
  });

  it.each([
    '/api/v1/clients',
    '/private/panel-other/api/v1/clients',
    '/private/panel/api/admin/interface',
    '/private/panel/api/v1/clients/%31',
  ])('keeps mounted Bearer credentials restricted at %s', async (path) => {
    auth.baseURL = '/private/panel/';
    auth.getHeader.mockReturnValue(`Bearer ${token}`);
    auth.getRequestURL.mockReturnValue(new URL(path, 'https://example.com'));
    auth.getSession.mockResolvedValue({ data: { userId: user.id } });
    await expect(getCurrentUser(event())).rejects.toMatchObject({
      statusCode: 403,
    });
    expect(auth.getSessionConfig).not.toHaveBeenCalled();
    expect(auth.getUser).not.toHaveBeenCalled();
  });

  it('leaves cookie sessions with verified TOTP working', async () => {
    const account = { ...user, totpVerified: true };
    auth.getSession.mockResolvedValue({ data: { userId: user.id } });
    auth.getUser.mockResolvedValue(account);
    await expect(getCurrentUser(event())).resolves.toBe(account);
    expect(auth.getByUsername).not.toHaveBeenCalled();
  });

  it('leaves existing Basic authentication working', async () => {
    auth.getHeader.mockReturnValue(
      `Basic ${Buffer.from('integration:password').toString('base64')}`
    );
    await expect(getCurrentUser(event())).resolves.toBe(user);
    expect(auth.isPasswordValid).toHaveBeenCalledExactlyOnceWith(
      'password',
      user.password
    );
  });

  it('continues rejecting Basic authentication with verified TOTP', async () => {
    auth.getHeader.mockReturnValue(
      `Basic ${Buffer.from('integration:password').toString('base64')}`
    );
    auth.getByUsername.mockResolvedValue({ ...user, totpVerified: true });
    await expect(getCurrentUser(event())).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('continues enforcing disabled password authentication for Basic', async () => {
    auth.getHeader.mockReturnValue('Basic test');
    auth.env.DISABLE_PASSWORD_AUTH = true;
    await expect(getCurrentUser(event())).rejects.toMatchObject({
      statusCode: 403,
    });
    expect(auth.isPasswordValid).not.toHaveBeenCalled();
  });

  it('continues rejecting disabled cookie session accounts', async () => {
    auth.getSession.mockResolvedValue({ data: { userId: user.id } });
    auth.getUser.mockResolvedValue({ ...user, enabled: false });
    await expect(getCurrentUser(event())).rejects.toMatchObject({
      statusCode: 403,
    });
  });
});
