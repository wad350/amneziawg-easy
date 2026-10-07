import {
  createError,
  readValidatedBody,
  setHeader,
  setResponseStatus,
} from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { toIntegrationClient } from '#server/utils/integrationApi';
import { IntegrationClientCreateSchema } from '#server/utils/integrationApiSchemas';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'clients',
  'create',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const data = await readValidatedBody(
      event,
      validateZod(IntegrationClientCreateSchema, event)
    );
    const result = await Database.clients.create(data);
    await WireGuard.saveConfig();
    const clientId = result[0]!.clientId;
    const client = await Database.clients.get(clientId);
    if (!client)
      throw createError({
        statusCode: 500,
        statusMessage: 'Client unavailable',
      });
    const iface = await Database.interfaces.get();
    const defaults = await Database.userConfigs.get();
    setResponseStatus(event, 201);
    return {
      success: true,
      client: toIntegrationClient(client, iface, defaults, {
        enableIpv6: !WG_ENV.DISABLE_IPV6,
      }),
    };
  }
);
