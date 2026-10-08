import { createServer } from 'node:http';
import type { Server } from 'node:http';

import {
  createApp,
  createError,
  defineEventHandler,
  getRequestURL,
  sendRedirect,
  toNodeListener,
} from 'h3';
import type { App, H3Event } from 'h3';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import {
  getAppPath,
  getAppRelativePath,
  getAppRequestURL,
  relativeAppPath,
} from '../../server/utils/appPath';
import setup from '../../server/middleware/setup';
import integrationCache from '../../server/middleware/integrationCache';
import appBase from '../../server/plugins/appBase';

const runtime = vi.hoisted(() => ({
  baseURL: '/',
  getSetupStep: vi.fn(),
}));

vi.mock('nitropack/runtime', () => ({
  useRuntimeConfig: () => ({ app: { baseURL: runtime.baseURL } }),
  defineNitroPlugin: (plugin: unknown) => plugin,
}));
vi.mock('#server/utils/Database', () => ({
  default: { general: { getSetupStep: runtime.getSetupStep } },
}));

const servers: Server[] = [];

function nativeApp() {
  const hooks: Array<(event: H3Event) => void | Promise<void>> = [];
  const captured: unknown[] = [];
  appBase({
    hooks: {
      hook: (
        name: string,
        handler: (event: H3Event) => void | Promise<void>
      ) => {
        if (name === 'request') hooks.push(handler);
      },
    },
  } as unknown as Parameters<typeof appBase>[0]);
  const app = createApp({
    onRequest: async (event) => {
      // Match Nitro's request-hook dispatcher: thrown errors are captured.
      await (async () => {
        for (const hook of hooks) await hook(event);
      })().catch((error) => captured.push(error));
    },
  });
  // Nitro's global route-rule handler runs before its mounted route handlers.
  app.use(defineEventHandler(() => undefined));
  return { app, captured };
}

async function listen(app: App) {
  const server = createServer(toNodeListener(app));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  return (path: string) =>
    fetch(`http://127.0.0.1:${address.port}${path}`, { redirect: 'manual' });
}

beforeEach(() => {
  runtime.baseURL = '/';
  runtime.getSetupStep.mockReset();
  runtime.getSetupStep.mockResolvedValue({ done: true, step: 0 });
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

describe('mounted native server paths', () => {
  test('handles the original root deployment unchanged', async () => {
    const { app } = nativeApp();
    app.use(
      '/',
      defineEventHandler((event) => ({
        relative: getAppRelativePath(event),
        login: getAppPath(event, '/login'),
      }))
    );
    const request = await listen(app);
    expect(await (await request('/api/v1/clients')).json()).toEqual({
      relative: '/api/v1/clients',
      login: '/login',
    });
  });

  test('uses originalUrl after the actual H3 mount strips event.path', async () => {
    runtime.baseURL = '/private/panel/';
    const { app } = nativeApp();
    app.use(
      runtime.baseURL,
      defineEventHandler((event) => ({
        mounted: event.path,
        original: getRequestURL(event).pathname,
        relative: getAppRelativePath(event),
        login: getAppPath(event, '/login'),
      }))
    );
    const request = await listen(app);
    expect(
      await (await request('/private/panel/api/v1/clients')).json()
    ).toEqual({
      mounted: '/api/v1/clients',
      original: '/private/panel/api/v1/clients',
      relative: '/api/v1/clients',
      login: '/private/panel/login',
    });
    expect((await request('/api/v1/clients')).status).toBe(404);
    expect((await request('/private/panel-other/api/v1/clients')).status).toBe(
      404
    );
  });

  test('does not decode token-controlled route IDs or strip a partial prefix', () => {
    expect(
      relativeAppPath('/private/panel/', '/private/panel/api/v1/clients/%31')
    ).toBe('/api/v1/clients/%31');
    expect(
      relativeAppPath('/private/panel/', '/private/panel-other/api/v1/clients')
    ).toBeUndefined();
    expect(
      relativeAppPath('/private/panel/', '/api/v1/clients')
    ).toBeUndefined();
    expect(relativeAppPath('/private/panel/', '/private/panel')).toBe('/');
  });

  test('ends unprefixed requests before a global SSR redirect, despite swallowed hook errors', async () => {
    runtime.baseURL = '/private/panel/';
    const control = createApp({
      onRequest: async () => {
        await Promise.reject(createError({ statusCode: 404 })).catch(() => {});
      },
    });
    control.use(
      defineEventHandler((event) => sendRedirect(event, '/private/panel/login'))
    );
    const controlRequest = await listen(control);
    expect((await controlRequest('/')).status).toBe(302);

    const { app, captured } = nativeApp();
    app.use(
      defineEventHandler((event) => sendRedirect(event, '/private/panel/login'))
    );
    const request = await listen(app);
    for (const path of [
      '/',
      '/login',
      '/api/session',
      '/api/v1/clients',
      '/_nuxt/app.js',
    ]) {
      const response = await request(path);
      expect(response.status).toBe(404);
      expect(response.headers.get('Location')).toBeNull();
      expect(await response.text()).toBe('');
    }
    expect(captured).toEqual([]);
  });

  test('keeps an OAuth callback prefix and query exactly once', async () => {
    runtime.baseURL = '/private/panel/';
    const { app } = nativeApp();
    app.use(
      runtime.baseURL,
      defineEventHandler((event) => {
        const url = getAppRequestURL(event);
        return { pathname: url.pathname, search: url.search };
      })
    );
    const request = await listen(app);
    expect(
      await (
        await request(
          '/private/panel/api/auth/oidc/callback?code=a%2Fb&state=abc'
        )
      ).json()
    ).toEqual({
      pathname: '/private/panel/api/auth/oidc/callback',
      search: '?code=a%2Fb&state=abc',
    });
  });
});

describe('setup and integration middleware under a base path', () => {
  async function middlewareApp() {
    const { app } = nativeApp();
    app.use(runtime.baseURL, setup);
    app.use(runtime.baseURL, integrationCache);
    app.use(
      runtime.baseURL,
      defineEventHandler(() => ({ reached: true }))
    );
    return listen(app);
  }

  test('allows mounted API and locale requests while setup is unfinished', async () => {
    runtime.baseURL = '/private/panel/';
    runtime.getSetupStep.mockResolvedValue({ done: false, step: 1 });
    const request = await middlewareApp();
    expect((await request('/private/panel/api/setup/2')).status).toBe(200);
    expect(
      (await request('/private/panel/_i18n/hash/en/messages.json')).status
    ).toBe(200);
    expect(runtime.getSetupStep).not.toHaveBeenCalled();
  });

  test.each(['/', '/private/panel/'])(
    'redirects first setup under %s',
    async (baseURL) => {
      runtime.baseURL = baseURL;
      runtime.getSetupStep.mockResolvedValue({ done: false, step: 1 });
      const request = await middlewareApp();
      const response = await request(baseURL);
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe(baseURL + 'setup/1');
    }
  );

  test('keeps setup progression and the completed-login redirect inside the mount', async () => {
    runtime.baseURL = '/private/panel/';
    const request = await middlewareApp();
    runtime.getSetupStep.mockResolvedValue({ done: false, step: 3 });
    let response = await request('/private/panel/setup/2');
    expect(response.headers.get('Location')).toBe('/private/panel/setup/3');
    runtime.getSetupStep.mockResolvedValue({ done: true, step: 0 });
    response = await request('/private/panel/setup/1');
    expect(response.headers.get('Location')).toBe('/private/panel/login');
  });

  test('keeps mounted integration responses out of caches', async () => {
    runtime.baseURL = '/private/panel/';
    const request = await middlewareApp();
    const response = await request('/private/panel/api/v1/clients');
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(
      (await request('/private/panel/api/client')).headers.get('Cache-Control')
    ).toBeNull();
  });
});
