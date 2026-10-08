import { createError, getHeader, getSession, useSession } from 'h3';
import type { H3Event } from 'h3';

import Database from '#server/utils/Database';
import { WG_ENV } from '#server/utils/config';
import { isPasswordValid } from '#server/utils/password';
import type { ID } from '#server/utils/types';
import type { UserType } from '#db/repositories/user/types';
import { getAppRelativePath } from '#server/utils/appPath';
import {
  ApiTokenError,
  authenticateApiToken,
  isApiBearerAuthorization,
} from '#server/utils/apiToken';

export type WGSession = Partial<{
  userId: ID;
  pendingLogin: {
    type: 'password' | 'oauth';
    userId: ID;
    remember: boolean;
    /** in milliseconds */
    expires_at: number;
  };
  oauth_verifier: string;
  oauth_nonce: string;
  oauth_state: string;
}>;

const name = 'wg-easy';

export async function useWGSession(event: H3Event, rememberMe = false) {
  const sessionConfig = await Database.general.getSessionConfig();
  return useSession<WGSession>(event, {
    password: sessionConfig.sessionPassword,
    name,
    // TODO: add session expiration
    // maxAge: undefined
    cookie: {
      maxAge: rememberMe ? sessionConfig.sessionTimeout : undefined,
      secure: !WG_ENV.INSECURE,
    },
  });
}

export async function getWGSession(event: H3Event) {
  const sessionConfig = await Database.general.getSessionConfig();
  return getSession<WGSession>(event, {
    password: sessionConfig.sessionPassword,
    name,
    cookie: {
      secure: !WG_ENV.INSECURE,
    },
  });
}

/**
 * @throws
 */
export async function getCurrentUser(event: H3Event) {
  const authorization = getHeader(event, 'Authorization');
  const rawAuthorizations: string[] = [];
  const rawHeaders = event.node.req.rawHeaders ?? [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === 'authorization') {
      rawAuthorizations.push(rawHeaders[index + 1] ?? '');
    }
  }
  const tokenAuthorization =
    rawAuthorizations.length > 1 ? rawAuthorizations : authorization;

  // An explicit Bearer attempt must never fall back to a logged-in cookie.
  if (isApiBearerAuthorization(tokenAuthorization)) {
    try {
      return await authenticateApiToken(
        {
          authorization: tokenAuthorization,
          method: event.method,
          path: getAppRelativePath(event) ?? '',
        },
        {
          sha256: process.env.AWG_API_TOKEN_SHA256,
          username: process.env.AWG_API_TOKEN_USER,
        },
        (username) => Database.users.getByUsername(username)
      );
    } catch (error) {
      if (error instanceof ApiTokenError) {
        throw createError({
          statusCode: error.statusCode,
          statusMessage: error.message,
        });
      }
      throw error;
    }
  }

  const session = await getWGSession(event);

  let user: UserType | undefined;
  if (session.data.userId) {
    // Handle if authenticating using Session
    user = await Database.users.get(session.data.userId);
  } else if (authorization) {
    if (WG_ENV.DISABLE_PASSWORD_AUTH) {
      throw createError({
        statusCode: 403,
        statusMessage: 'Password authentication is disabled',
      });
    }

    // Handle if authenticating using Header
    const [method, value] = authorization.split(' ');
    // Support Basic Authentication
    if (method !== 'Basic' || !value) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid Basic Authorization',
      });
    }

    const basicValue = Buffer.from(value, 'base64').toString('utf-8');

    // Split by first ":"
    const index = basicValue.indexOf(':');
    const username = basicValue.substring(0, index);
    const password = basicValue.substring(index + 1);

    if (!username || !password) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid Basic Authorization',
      });
    }

    const foundUser = await Database.users.getByUsername(username);

    // always check to avoid timing attack
    const userHashPassword = foundUser?.password ?? null;
    const passwordValid = await isPasswordValid(password, userHashPassword);

    // can't login through basic auth if 2fa enabled
    if (!foundUser || !passwordValid || foundUser.totpVerified) {
      throw createError({
        statusCode: 401,
        statusMessage: 'Session failed',
      });
    }
    user = foundUser;
  } else {
    throw createError({
      statusCode: 401,
      statusMessage: 'Session failed. No Authorization',
    });
  }

  if (!user) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Session failed. User not found',
    });
  }

  if (!user.enabled) {
    throw createError({
      statusCode: 403,
      statusMessage: 'User is disabled',
    });
  }

  return user;
}
