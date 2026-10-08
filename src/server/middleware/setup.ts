import { defineEventHandler, sendRedirect } from 'h3';

import Database from '#server/utils/Database';
import { getAppPath, getAppRelativePath } from '#server/utils/appPath';

/* First setup of wg-easy */
export default defineEventHandler(async (event) => {
  const path = getAppRelativePath(event);
  if (path === undefined) return;

  // User can't be logged in, and public routes can be accessed whenever
  if (path.startsWith('/api/') || path.startsWith('/_i18n/')) {
    return;
  }

  const { step, done } = await Database.general.getSetupStep();
  if (!done) {
    const parsedSetup = path.match(/\/setup\/(\d)/);
    if (!parsedSetup) {
      return sendRedirect(event, getAppPath(event, '/setup/1'), 302);
    }
    const [_, currentSetup] = parsedSetup;

    if (step.toString() === currentSetup) {
      return;
    }
    return sendRedirect(event, getAppPath(event, `/setup/${step}`), 302);
  } else {
    // If already set up
    if (!path.startsWith('/setup/')) {
      return;
    }
    return sendRedirect(event, getAppPath(event, '/login'), 302);
  }
});
