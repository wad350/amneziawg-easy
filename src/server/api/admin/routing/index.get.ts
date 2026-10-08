import { setHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { loadRoutingConfig } from '#server/utils/routingStore';
import { getRoutingStatus } from '#server/utils/routingRuntime';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    return { config: await loadRoutingConfig(), status: getRoutingStatus() };
  }
);
