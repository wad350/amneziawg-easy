/** Resolve raw browser links under the Nuxt application base path. */
export function resolveAppPath(baseURL: string, path: string): string {
  // External URLs, blob/data URLs and local SVG fragments are already complete.
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(path)) return path;

  const base = `/${baseURL.replace(/^\/+|\/+$/g, '')}/`.replace(/\/+/g, '/');
  const prefix = base === '/' ? '' : base.slice(0, -1);
  if (
    prefix &&
    (path === prefix ||
      path.startsWith(`${prefix}/`) ||
      path.startsWith(`${prefix}?`) ||
      path.startsWith(`${prefix}#`))
  ) {
    return path;
  }
  return base + path.replace(/^(?:\.\/|\/)+/g, '');
}
