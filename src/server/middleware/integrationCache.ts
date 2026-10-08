import { defineEventHandler, setHeader } from 'h3';

import { getAppRelativePath } from '#server/utils/appPath';

export default defineEventHandler((event) => {
  const path = getAppRelativePath(event);
  if (path === '/api/v1' || path?.startsWith('/api/v1/'))
    setHeader(event, 'Cache-Control', 'no-store');
});
