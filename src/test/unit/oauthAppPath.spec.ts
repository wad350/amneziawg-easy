import { createServer } from 'node:http';
import type { Server } from 'node:http';

import {
  createApp,
  createRouter,
  defineEventHandler,
  toNodeListener,
} from 'h3';
import type { EventHandler, H3Event } from 'h3';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import oauthStart from '../../server/api/auth/[provider]/index.get';
import oauthCallback from '../../server/api/auth/[provider]/callback.get';
import oauthLink from '../../server/api/auth/[provider]/link.get';

const oauth = vi.hoisted(() => ({
  baseURL: '/',
  discovery: vi.fn(),
  buildAuthorizationUrl: vi.fn(),
  authorizationCodeGrant: vi.fn(),
  fetchUserInfo: vi.fn(),
  updateSession: vi.fn(),
  loginWithOAuth: vi.fn(),
  linkOauth: vi.fn(),
  insecure: false,
}));

vi.mock('nitropack/runtime', () => ({
  useRuntimeConfig: () => ({ app: { baseURL: oauth.baseURL } }),
}));
vi.mock('#server/utils/config', () => ({
  WG_ENV: {
    get INSECURE() {
      return oauth.insecure;
    },
    OAUTH_PROVIDERS: ['google'],
  },
  SERVER_DEBUG: vi.fn(),
}));
vi.mock('#server/utils/Database', () => ({
  default: {
    users: {
      loginWithOAuth: oauth.loginWithOAuth,
      linkOauth: oauth.linkOauth,
    },
  },
}));
vi.mock('#server/utils/session', () => ({
  useWGSession: () => ({
    data: {
      oauth_nonce: 'fixture-nonce',
      oauth_verifier: 'fixture-verifier',
      oauth_state: 'fixture-state',
    },
    update: oauth.updateSession,
  }),
}));
vi.mock('#server/utils/handler', () => ({
  definePermissionEventHandler: (
    _resource: string,
    _action: string,
    handler: (params: {
      event: H3Event;
      user: { id: number };
      checkPermissions: (user: unknown) => void;
    }) => unknown
  ) =>
    defineEventHandler((event) =>
      handler({ event, user: { id: 42 }, checkPermissions: vi.fn() })
    ),
}));
vi.mock('openid-client', () => ({
  discovery: oauth.discovery,
  randomPKCECodeVerifier: () => 'fixture-verifier',
  calculatePKCECodeChallenge: async () => 'fixture-challenge',
  randomNonce: () => 'fixture-nonce',
  randomState: () => 'fixture-state',
  buildAuthorizationUrl: oauth.buildAuthorizationUrl,
  authorizationCodeGrant: oauth.authorizationCodeGrant,
  fetchUserInfo: oauth.fetchUserInfo,
}));

const servers: Server[] = [];

async function requestHandler(path: string, handler: EventHandler) {
  const app = createApp();
  const router = createRouter();
  router.get(path, handler);
  app.use(oauth.baseURL, router.handler);
  const server = createServer(toNodeListener(app));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  const origin = `http://127.0.0.1:${address.port}`;
  return {
    origin,
    request: (pathname: string) =>
      fetch(origin + oauth.baseURL + pathname, { redirect: 'manual' }),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  oauth.baseURL = '/';
  oauth.insecure = false;
  oauth.discovery.mockResolvedValue({});
  oauth.buildAuthorizationUrl.mockImplementation((_config, parameters) => {
    const url = new URL('https://identity.example/authorize');
    url.search = new URLSearchParams(parameters).toString();
    return url;
  });
  oauth.authorizationCodeGrant.mockResolvedValue({
    claims: () => ({ sub: 'fixture-user' }),
    access_token: 'fixture-access-token',
  });
  oauth.fetchUserInfo.mockResolvedValue({
    sub: 'fixture-user',
    email: 'fixture@example.com',
    email_verified: true,
  });
  oauth.updateSession.mockResolvedValue({ id: 'fixture-session' });
  oauth.loginWithOAuth.mockResolvedValue({
    success: true,
    user: { id: 42, username: 'fixture' },
  });
});

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve()))
          )
      )
  );
});

describe('OAuth native routes under an application base', () => {
  test.each(['/', '/private/panel/'])(
    'uses the public callback under %s without changing the provider URL or PKCE',
    async (baseURL) => {
      oauth.baseURL = baseURL;
      const { request, origin } = await requestHandler(
        '/api/auth/:provider',
        oauthStart
      );
      const response = await request('api/auth/google');
      expect(response.status).toBe(302);
      const location = new URL(response.headers.get('Location')!);
      expect(location.origin + location.pathname).toBe(
        'https://identity.example/authorize'
      );
      expect(location.searchParams.get('redirect_uri')).toBe(
        origin.replace('http:', 'https:') + baseURL + 'api/auth/google/callback'
      );
      expect(location.searchParams.get('state')).toBe('fixture-state');
      expect(location.searchParams.get('code_challenge')).toBe(
        'fixture-challenge'
      );
      expect(location.searchParams.get('code_challenge_method')).toBe('S256');
      expect(oauth.updateSession).toHaveBeenCalledWith({
        oauth_nonce: 'fixture-nonce',
        oauth_verifier: 'fixture-verifier',
        oauth_state: 'fixture-state',
      });
    }
  );

  test('uses the prefixed link callback while preserving explicit insecure mode', async () => {
    oauth.baseURL = '/private/panel/';
    oauth.insecure = true;
    const { request, origin } = await requestHandler(
      '/api/auth/:provider',
      oauthStart
    );
    const response = await request('api/auth/google?link=true');
    const location = new URL(response.headers.get('Location')!);
    expect(location.searchParams.get('redirect_uri')).toBe(
      origin + '/private/panel/api/auth/google/link'
    );
  });

  test.each(['/', '/private/panel/'])(
    'exchanges the actual callback query and redirects inside %s',
    async (baseURL) => {
      oauth.baseURL = baseURL;
      const { request, origin } = await requestHandler(
        '/api/auth/:provider/callback',
        oauthCallback
      );
      const response = await request(
        'api/auth/google/callback?code=a%2Fb&state=fixture-state'
      );
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe(baseURL);
      const [, currentURL, checks] =
        oauth.authorizationCodeGrant.mock.calls[0]!;
      expect(currentURL.href).toBe(
        origin +
          baseURL +
          'api/auth/google/callback?code=a%2Fb&state=fixture-state'
      );
      expect(checks).toMatchObject({
        pkceCodeVerifier: 'fixture-verifier',
        expectedState: 'fixture-state',
        expectedNonce: 'fixture-nonce',
      });
    }
  );

  test('keeps the pending second-factor redirect inside the base', async () => {
    oauth.baseURL = '/private/panel/';
    oauth.loginWithOAuth.mockResolvedValue({
      success: false,
      error: 'TOTP_REQUIRED',
      userId: 42,
    });
    const { request } = await requestHandler(
      '/api/auth/:provider/callback',
      oauthCallback
    );
    const response = await request(
      'api/auth/google/callback?code=fixture&state=fixture-state'
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/private/panel/login/2fa');
  });

  test('returns to the prefixed account page after linking', async () => {
    oauth.baseURL = '/private/panel/';
    const { request } = await requestHandler(
      '/api/auth/:provider/link',
      oauthLink
    );
    const response = await request(
      'api/auth/google/link?code=fixture&state=fixture-state'
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/private/panel/me');
    expect(oauth.linkOauth).toHaveBeenCalledWith(42, 'google', 'fixture-user');
  });
});
