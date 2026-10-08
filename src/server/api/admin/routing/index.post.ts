import { createError, readValidatedBody, setHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingSaveSchema } from '#shared/types/routing';
import { validateRoutingConfig } from '#server/utils/routingConfig';
import { getRoutingContext } from '#server/utils/routingContext';
import { saveAndApplyRouting } from '#server/utils/routingRuntime';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const data = await readValidatedBody(
      event,
      validateZod(RoutingSaveSchema, event)
    );
    const context = await getRoutingContext();
    const config = validateRoutingConfig(data.config, context);
    try {
      return {
        success: true,
        status: await saveAndApplyRouting(config, context, data.apply),
      };
    } catch {
      throw createError({
        statusCode: 400,
        statusMessage:
          'Routing configuration could not be saved or applied; private output withheld',
      });
    }
  }
);
