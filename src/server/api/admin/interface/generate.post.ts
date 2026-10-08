import { createError, setResponseHeader } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';
import { WG_ENV } from '#server/utils/config';
import { generateAwg31Parameters } from '#server/utils/amneziawg';

/** Preview only: never writes the database, server configuration, or clients. */
export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    if (WG_ENV.WG_EXECUTABLE !== 'awg') {
      throw createError({
        statusCode: 400,
        statusMessage: 'AmneziaWG is disabled',
      });
    }
    setResponseHeader(event, 'Cache-Control', 'no-store');
    return generateAwg31Parameters();
  }
);
