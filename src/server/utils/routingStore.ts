import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  RoutingConfigSchema,
  type RoutingConfig,
} from '../../shared/types/routing';

import { validateRoutingConfig, RoutingValidationError } from './routingConfig';

export const ROUTING_DATA_DIR = process.env.WG_DATA_DIR || '/etc/wireguard';
if (!isAbsolute(ROUTING_DATA_DIR))
  throw new RoutingValidationError('WG_DATA_DIR must be absolute');
export const ROUTING_CONFIG_PATH = join(
  ROUTING_DATA_DIR,
  'awg-easy-routing.json'
);
export const ROUTING_APPLIED_PATH = join(
  ROUTING_DATA_DIR,
  'awg-easy-routing.applied.json'
);
const LIMIT = 4 * 1024 * 1024;

export async function writeRoutingFile(
  path: string,
  body: string
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.tmp`;
  const file = await open(
    temporary,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600
  );
  try {
    await file.writeFile(body);
    await file.sync();
    await file.close();
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY);
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch {
    await file.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw new RoutingValidationError(
      'Could not atomically save private routing data'
    );
  }
}

export async function loadRoutingConfig(
  path = ROUTING_CONFIG_PATH
): Promise<RoutingConfig> {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      return RoutingConfigSchema.parse({});
    throw new RoutingValidationError(
      'Cannot read private routing configuration'
    );
  }
  if (
    !info.isFile() ||
    (info.mode & 0o077) !== 0 ||
    info.size > LIMIT ||
    info.uid !== process.getuid?.()
  )
    throw new RoutingValidationError(
      'Routing configuration must be an owner-only regular file'
    );
  try {
    return validateRoutingConfig(JSON.parse(await readFile(path, 'utf8')));
  } catch {
    throw new RoutingValidationError(
      'Stored routing configuration failed validation'
    );
  }
}

export async function saveRoutingConfig(
  config: RoutingConfig,
  path = ROUTING_CONFIG_PATH
): Promise<void> {
  const validated = validateRoutingConfig(config);
  const body = JSON.stringify(validated, null, 2) + '\n';
  if (Buffer.byteLength(body) > LIMIT)
    throw new RoutingValidationError(
      'Routing configuration exceeds size limit'
    );
  await writeRoutingFile(path, body);
}

/** Draft saves never change the configuration restored at container startup. */
export function loadAppliedRoutingConfig(path = ROUTING_APPLIED_PATH) {
  return loadRoutingConfig(path);
}

export function saveAppliedRoutingConfig(
  config: RoutingConfig,
  path = ROUTING_APPLIED_PATH
) {
  return saveRoutingConfig(config, path);
}
