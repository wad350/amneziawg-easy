import { getRequestURL } from 'h3';
import type { H3Event } from 'h3';
import { useRuntimeConfig } from 'nitropack/runtime';

import { resolveAppPath } from '../../shared/utils/appPath';

/** Strip only the configured application prefix, without decoding route IDs. */
export function relativeAppPath(baseURL: string, pathname: string) {
  const base = resolveAppPath(baseURL, '/');
  if (base === '/') return pathname;

  const prefix = base.slice(0, -1);
  if (pathname === prefix) return '/';
  if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
  return undefined;
}

export function getAppPath(event: H3Event, path: string) {
  return resolveAppPath(useRuntimeConfig(event).app.baseURL, path);
}

/** H3 keeps originalUrl even after Nitro strips the mount from event.path. */
export function getAppRelativePath(event: H3Event) {
  return relativeAppPath(
    useRuntimeConfig(event).app.baseURL,
    getRequestURL(event).pathname
  );
}

/** Preserve the OAuth callback query and its public application prefix. */
export function getAppRequestURL(event: H3Event) {
  const url = getRequestURL(event);
  url.pathname = getAppPath(event, url.pathname);
  return url;
}
