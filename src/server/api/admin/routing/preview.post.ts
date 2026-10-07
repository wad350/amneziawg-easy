import { createError, readValidatedBody, setHeader } from 'h3';
import z from 'zod';

import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingConfigSchema } from '#shared/types/routing';
import { getRoutingContext } from '#server/utils/routingContext';
import { previewRouting } from '#server/utils/routingRender';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const data = await readValidatedBody(
      event,
      validateZod(z.object({ config: RoutingConfigSchema }).strict(), event)
    );
    try {
      return previewRouting(data.config, await getRoutingContext());
    } catch {
      throw createError({
        statusCode: 400,
        statusMessage:
          'Routing preview failed validation; private values withheld',
      });
    }
  }
);
