import { setHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationRouting } from '#server/utils/integrationApi';
import { getRoutingStatus } from '#server/utils/routingRuntime';
import { loadRoutingConfig } from '#server/utils/routingStore';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    return toIntegrationRouting(await loadRoutingConfig(), getRoutingStatus());
  }
);
