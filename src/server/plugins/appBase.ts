import { sendNoContent } from 'h3';
import { defineNitroPlugin } from 'nitropack/runtime';

import { getAppRelativePath } from '#server/utils/appPath';

export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook('request', (event) => {
    if (getAppRelativePath(event) !== undefined) return;

    // Nitro catches errors thrown by request hooks. End this response instead
    // so its global SSR fallback cannot redirect outside the application mount.
    sendNoContent(event, 404);
  });
});
