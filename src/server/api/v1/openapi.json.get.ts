import { setHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { integrationOpenApi } from '#server/utils/integrationOpenApi';
import { getAppPath } from '#server/utils/appPath';

export default definePermissionEventHandler(
  'clients',
  'custom',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    return integrationOpenApi(getAppPath(event, '/'));
  }
);
