import { resolveAppPath } from '#shared/utils/appPath';

/** Raw DOM URLs need the base path; Nuxt navigation and $fetch already use it. */
export function useAppPath() {
  const config = useRuntimeConfig();
  return (path: string) => resolveAppPath(config.app.baseURL, path);
}
