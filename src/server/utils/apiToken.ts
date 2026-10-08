import { createHash, timingSafeEqual } from 'node:crypto';

export interface ApiTokenConfig {
  sha256: string | undefined;
  username: string | undefined;
}

export interface ApiTokenAccount {
  enabled: boolean;
  totpVerified: boolean;
}

export interface ApiTokenRequest {
  authorization: string | readonly string[] | undefined;
  method: string;
  path: string;
}

export class ApiTokenError extends Error {
  constructor(
    readonly statusCode: 401 | 403,
    message: string
  ) {
    super(message);
    this.name = 'ApiTokenError';
  }
}

function authorizationValues(
  authorization: ApiTokenRequest['authorization']
): readonly string[] {
  return typeof authorization === 'string'
    ? [authorization]
    : (authorization ?? []);
}

/** Detect explicit Bearer attempts before a session cookie can take precedence. */
export function isApiBearerAuthorization(
  authorization: ApiTokenRequest['authorization']
): boolean {
  const values = authorizationValues(authorization);
  return values.some((value) => /(?:^|,)\s*bearer/i.test(value));
}

/** Service credentials can access only the versioned integration contract. */
export function isApiTokenOperationAllowed(method: string, path: string) {
  const verb = method.toUpperCase();
  const getPaths = new Set([
    '/api/v1/server',
    '/api/v1/openapi.json',
    '/api/v1/clients',
    '/api/v1/routing',
  ]);
  if (verb === 'GET' && getPaths.has(path)) return true;
  if (verb === 'POST' && path === '/api/v1/clients') return true;
  if (verb === 'PUT' && path === '/api/v1/routing/rules') return true;

  const clientPath = path.match(
    /^\/api\/v1\/clients\/([1-9]\d*)(\/(?:configuration|qrcode\.svg))?$/
  );
  if (!clientPath || !Number.isSafeInteger(Number(clientPath[1]))) return false;
  if (verb === 'GET') return true;
  return !clientPath[2] && (verb === 'PATCH' || verb === 'DELETE');
}

function unauthorized(): never {
  throw new ApiTokenError(401, 'API token authentication failed');
}

/**
 * Authenticate an opt-in service token without storing or logging its plaintext.
 * User state is resolved on every request; route handlers still enforce roles
 * and resource ownership using the application's existing permission checks.
 */
export async function authenticateApiToken<User extends ApiTokenAccount>(
  request: ApiTokenRequest,
  config: ApiTokenConfig,
  resolveUser: (username: string) => Promise<User | undefined>
): Promise<User> {
  const values = authorizationValues(request.authorization);
  if (values.length !== 1) unauthorized();

  const match = values[0]!.match(/^Bearer (awg_[A-Za-z0-9_-]{43})$/i);
  const token = match?.[1];
  if (!token || !/^awg_[A-Za-z0-9_-]{43}$/.test(token)) unauthorized();
  const tokenBytes = Buffer.from(token.slice(4), 'base64url');
  if (
    tokenBytes.length !== 32 ||
    tokenBytes.toString('base64url') !== token.slice(4)
  ) {
    unauthorized();
  }

  const { sha256, username } = config;
  if (
    !sha256 ||
    !/^[a-f0-9]{64}$/i.test(sha256) ||
    !username ||
    username.trim() !== username ||
    [...username].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    unauthorized();
  }

  const suppliedDigest = createHash('sha256').update(token).digest();
  if (!timingSafeEqual(suppliedDigest, Buffer.from(sha256, 'hex'))) {
    unauthorized();
  }
  if (!isApiTokenOperationAllowed(request.method, request.path)) {
    throw new ApiTokenError(403, 'API token cannot access this operation');
  }

  const user = await resolveUser(username);
  if (!user) unauthorized();
  if (!user.enabled) throw new ApiTokenError(403, 'User is disabled');
  if (user.totpVerified) {
    throw new ApiTokenError(
      403,
      'API tokens are unavailable for accounts with two-factor authentication'
    );
  }
  return user;
}
