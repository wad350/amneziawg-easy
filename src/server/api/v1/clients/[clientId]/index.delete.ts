import { createError, getValidatedRouterParams, setHeader } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { IntegrationClientIdSchema } from '#server/utils/integrationApiSchemas';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'clients',
  'delete',
  async ({ event, checkPermissions }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(IntegrationClientIdSchema, event)
    );
    const client = await Database.clients.get(clientId);
    if (!client)
      throw createError({ statusCode: 404, statusMessage: 'Client not found' });
    checkPermissions(client);
    await Database.clients.delete(clientId);
    await WireGuard.saveConfig();
    return { success: true };
  }
);
