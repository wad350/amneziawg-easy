import {
  createError,
  getValidatedRouterParams,
  readValidatedBody,
  setHeader,
} from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationClient } from '#server/utils/integrationApi';
import { ClientEditableUpdateError } from '#db/repositories/client/types';
import {
  IntegrationClientIdSchema,
  IntegrationClientPatchSchema,
} from '#server/utils/integrationApiSchemas';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'clients',
  'update',
  async ({ event, checkPermissions }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(IntegrationClientIdSchema, event)
    );
    const patch = await readValidatedBody(
      event,
      validateZod(IntegrationClientPatchSchema, event)
    );
    const client = await Database.clients.get(clientId);
    if (!client)
      throw createError({ statusCode: 404, statusMessage: 'Client not found' });
    checkPermissions(client);
    try {
      await Database.clients.updateEditableFields(clientId, patch);
    } catch (error) {
      if (error instanceof ClientEditableUpdateError)
        throw createError({
          statusCode: error.statusCode,
          statusMessage: error.message,
        });
      throw error;
    }
    await WireGuard.saveConfig();
    const updated = await Database.clients.get(clientId);
    if (!updated)
      throw createError({ statusCode: 404, statusMessage: 'Client not found' });
    const iface = await Database.interfaces.get();
    const defaults = await Database.userConfigs.get();
    return {
      success: true,
      client: toIntegrationClient(updated, iface, defaults, {
        enableIpv6: !WG_ENV.DISABLE_IPV6,
      }),
    };
  }
);
