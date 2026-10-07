import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdir, rm, access, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

import {
  RoutingConfigSchema,
  type RoutingConfig,
  type RoutingStatus,
} from '../../shared/types/routing';

import {
  egressInterface,
  parseAwgProfile,
  renderAwgProfile,
  validateRoutingConfig,
  RoutingValidationError,
  type RoutingContext,
} from './routingConfig';
import {
  ROUTING_TABLE,
  ROUTING_GATE_TABLE,
  ROUTING_MARK,
  ROUTING_POLICY_TABLE,
  ROUTING_POLICY_PRIORITY,
  ROUTING_TPROXY_PORT,
  renderNftables,
  renderSingBox,
  renderRoutingGate,
} from './routingRender';
import {
  loadRoutingConfig,
  saveRoutingConfig,
  loadAppliedRoutingConfig,
  saveAppliedRoutingConfig,
  writeRoutingFile,
  ROUTING_DATA_DIR,
} from './routingStore';

const exec = promisify(execFile);
const RUNTIME_ROOT = `${ROUTING_DATA_DIR}/.awg-easy-routing-runtime`;
type OwnedRuntime = {
  child: ChildProcess | null;
  dir: string;
  config: RoutingConfig;
  context: RoutingContext;
  interfaces: string[];
  sourceRules: Array<{
    address: string;
    table: number;
    priority: number;
    route: boolean;
    rule: boolean;
  }>;
  nft: boolean;
  tproxyRoute: boolean;
  tproxyRule: boolean;
};
let current: OwnedRuntime | null = null;
type Snapshot = { config: RoutingConfig; context: RoutingContext };
let gateScopes: Snapshot[] | null = null;
let status: RoutingStatus = {
  state: 'stopped',
  enabled: false,
  pid: null,
  appliedAt: null,
  error: null,
};
let queue: Promise<unknown> = Promise.resolve();

/** Intentionally suppress subprocess output: tool errors can contain imported secrets. */
async function command(
  file: string,
  args: string[],
  timeout = 20000
): Promise<string> {
  try {
    const result = await exec(file, args, {
      timeout,
      maxBuffer: 1024 * 1024,
    });
    return result.stdout;
  } catch {
    throw new RoutingValidationError(
      `Routing operation failed (${file}); private output withheld`
    );
  }
}

async function guardedNamespace(): Promise<void> {
  if (
    process.platform !== 'linux' ||
    process.env.AWG_ISOLATED !== 'true' ||
    process.env.AWG_FORCE_USERSPACE !== 'true'
  )
    throw new RoutingValidationError(
      'Routing requires the dedicated isolated Docker namespace'
    );
  await access('/.dockerenv');
  await access('/dev/net/tun');
  let marker = '';
  try {
    marker = await readFile('/run/awg-easy-isolated-network', 'utf8');
  } catch {
    /* refuse absent marker */
  }
  if (marker.trim() !== 'bridge-tun-v1')
    throw new RoutingValidationError('Isolated namespace marker is missing');
  const links = JSON.parse(
    await command('ip', ['-j', '-d', 'link', 'show', 'dev', 'eth0'])
  ) as Array<{
    ifindex: number;
    link_index?: number;
    linkinfo?: { info_kind?: string };
  }>;
  const device = links[0];
  if (
    !device ||
    (device.linkinfo?.info_kind !== 'veth' &&
      (!device.link_index || device.link_index === device.ifindex))
  )
    throw new RoutingValidationError(
      'Routing requires a separate Docker bridge namespace'
    );
  const caps = (await readFile('/proc/self/status', 'utf8')).match(
    /^CapEff:\s*([0-9a-f]+)$/m
  )?.[1];
  if (!caps || (BigInt(`0x${caps}`) & (1n << 16n)) !== 0n)
    throw new RoutingValidationError(
      'SYS_MODULE capability is forbidden for routing'
    );
}

function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const result = queue.then(fn, fn);
  queue = result.catch(() => {});
  return result;
}

export function getRoutingStatus(): RoutingStatus {
  return { ...status };
}

async function terminate(child: ChildProcess): Promise<void> {
  if (!child.pid) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => {
      child.kill('SIGKILL');
    }, 3000);
    const finish = setTimeout(() => {
      clearTimeout(kill);
      resolve();
    }, 5000);
    child.once('exit', () => {
      clearTimeout(kill);
      clearTimeout(finish);
      resolve();
    });
    child.kill('SIGTERM');
  });
  if (child.exitCode === null && child.signalCode === null)
    throw new RoutingValidationError(
      'Routing process did not terminate; fail-closed gate is retained'
    );
}

async function cleanup(owned: OwnedRuntime): Promise<void> {
  // Delete only the named table and exact policy rules created by this controller.
  // Keep ownership and private files for retry when any exact deletion fails.
  let failed = false;
  const remove = async (file: string, args: string[], done: () => void) => {
    try {
      await command(file, args);
      done();
    } catch {
      failed = true;
    }
  };
  if (owned.nft)
    await remove('nft', ['delete', 'table', 'ip', ROUTING_TABLE], () => {
      owned.nft = false;
    });
  if (owned.tproxyRule) {
    await remove(
      'ip',
      [
        '-4',
        'rule',
        'del',
        'priority',
        String(ROUTING_POLICY_PRIORITY),
        'fwmark',
        `${ROUTING_MARK}/0xffffffff`,
        'table',
        String(ROUTING_POLICY_TABLE),
      ],
      () => {
        owned.tproxyRule = false;
      }
    );
  }
  if (owned.tproxyRoute) {
    await remove(
      'ip',
      [
        '-4',
        'route',
        'del',
        'local',
        '0.0.0.0/0',
        'dev',
        'lo',
        'table',
        String(ROUTING_POLICY_TABLE),
      ],
      () => {
        owned.tproxyRoute = false;
      }
    );
  }
  if (owned.child) await terminate(owned.child);
  for (const rule of owned.sourceRules.slice().reverse()) {
    if (rule.rule)
      await remove(
        'ip',
        [
          '-4',
          'rule',
          'del',
          'priority',
          String(rule.priority),
          'from',
          rule.address,
          'table',
          String(rule.table),
        ],
        () => {
          rule.rule = false;
        }
      );
    if (rule.route)
      await remove(
        'ip',
        ['-4', 'route', 'del', 'default', 'table', String(rule.table)],
        () => {
          rule.route = false;
        }
      );
  }
  for (const name of owned.interfaces.slice().reverse())
    await remove('awg-quick', ['down', `${owned.dir}/${name}.conf`], () => {
      owned.interfaces.splice(owned.interfaces.indexOf(name), 1);
    });
  if (failed)
    throw new RoutingValidationError(
      'Owned routing cleanup failed; fail-closed gate and retry state are retained'
    );
  await rm(owned.dir, { recursive: true, force: true });
}

async function removeGate(): Promise<void> {
  if (!gateScopes) return;
  await command('nft', ['delete', 'table', 'ip', ROUTING_GATE_TABLE]);
  gateScopes = null;
}

async function installGate(scopes: Snapshot[]): Promise<void> {
  await guardedNamespace();
  const tables = JSON.parse(await command('nft', ['-j', 'list', 'tables'])) as {
    nftables?: Array<{ table?: { family: string; name: string } }>;
  };
  if (
    !gateScopes &&
    tables.nftables?.some(
      (entry) =>
        entry.table?.family === 'ip' && entry.table.name === ROUTING_GATE_TABLE
    )
  )
    throw new RoutingValidationError(
      'Fail-closed table is occupied; refusing to replace it'
    );
  const combined = [...(gateScopes ?? []), ...scopes];
  const path = `${RUNTIME_ROOT}/gate.nft`;
  await writeRoutingFile(
    path,
    renderRoutingGate(combined, Boolean(gateScopes))
  );
  await command('nft', ['--check', '-f', path]);
  await command('nft', ['-f', path]);
  gateScopes = combined;
}

async function stopInternal(clearGate = true): Promise<void> {
  const owned = current;
  if (owned) {
    if (!gateScopes)
      await installGate([{ config: owned.config, context: owned.context }]);
    try {
      await cleanup(owned);
    } catch (error) {
      status = {
        state: 'failed',
        enabled: true,
        pid: null,
        appliedAt: status.appliedAt,
        error:
          'Owned routing cleanup failed; scoped fail-closed gate remains until repair',
      };
      throw error;
    }
    current = null;
  }
  if (clearGate) await removeGate();
  status = {
    state: 'stopped',
    enabled: Boolean(gateScopes),
    pid: null,
    appliedAt: null,
    error: null,
  };
}

export function stopRouting(
  options: { preserveGate?: boolean } = {}
): Promise<void> {
  return serialized(() => stopInternal(!options.preserveGate));
}

/** Arm only the explicitly applied policy before bringing the inbound AWG link up. */
export function armAppliedRoutingGate(
  context: RoutingContext,
  appliedConfigPath?: string
): Promise<RoutingStatus> {
  return serialized(async () => {
    const applied = await loadAppliedRoutingConfig(appliedConfigPath);
    if (!applied.enabled) return getRoutingStatus();
    const config = validateRoutingConfig(applied, context);
    await installGate([{ config, context }]);
    if (!current)
      status = {
        state: 'stopped',
        enabled: true,
        pid: null,
        appliedAt: null,
        error: null,
      };
    return getRoutingStatus();
  });
}

/** Match only a TCP listener owned by the exact child PID, never another process. */
export function ownsRoutingListener(output: string, pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  return output.split('\n').some((line) => {
    const fields = line.trim().split(/\s+/);
    if (
      fields[0] !== 'LISTEN' ||
      !fields[3]?.endsWith(`:${ROUTING_TPROXY_PORT}`)
    )
      return false;
    const processes = line.slice(line.indexOf('users:('));
    if (!processes.startsWith('users:(')) return false;
    return [...processes.matchAll(/\bpid=(\d+)(?=[,)])/g)].some(
      (match) => Number(match[1]) === pid
    );
  });
}

async function listenerReady(child: ChildProcess): Promise<void> {
  const deadline = performance.now() + 5000;
  const assertAlive = () => {
    if (!child.pid || child.exitCode !== null || child.signalCode !== null)
      throw new RoutingValidationError(
        'Routing process exited before becoming ready'
      );
  };
  while (performance.now() < deadline) {
    assertAlive();
    let listeners = '';
    try {
      // Inspect kernel socket state only. Connecting to a TProxy listener would
      // proxy its own probe back into itself and recursively create connections.
      listeners = await command(
        'ss',
        ['-H', '-lntp', 'sport', '=', `:${ROUTING_TPROXY_PORT}`],
        Math.max(1, Math.min(1000, Math.floor(deadline - performance.now())))
      );
    } catch {
      // Retry unavailable or not-yet-visible socket metadata within the deadline.
    }
    assertAlive();
    if (ownsRoutingListener(listeners, child.pid!)) return;
    const remaining = deadline - performance.now();
    if (remaining > 0)
      await new Promise((resolve) =>
        setTimeout(resolve, Math.min(100, remaining))
      );
  }
  throw new RoutingValidationError('Routing listener did not become ready');
}

async function prepare(
  config: RoutingConfig,
  context: RoutingContext
): Promise<string> {
  await guardedNamespace();
  await mkdir(RUNTIME_ROOT, { recursive: true, mode: 0o700 });
  const dir = `${RUNTIME_ROOT}/${randomUUID()}`;
  await mkdir(dir, { mode: 0o700 });
  try {
    await writeRoutingFile(
      `${dir}/sing-box.json`,
      JSON.stringify(
        renderSingBox(config, {
          debug: process.env.AWG_ROUTING_DEBUG === 'true',
        })
      )
    );
    await writeRoutingFile(
      `${dir}/routes.nft`,
      renderNftables(config, context)
    );
    await writeRoutingFile(
      `${dir}/check.nft`,
      renderNftables(config, context, Boolean(current?.nft))
    );
    for (const egress of config.egresses)
      await writeRoutingFile(
        `${dir}/${egressInterface(egress.id)}.conf`,
        renderAwgProfile(parseAwgProfile(egress.profile))
      );
    await command('sing-box', ['check', '-c', `${dir}/sing-box.json`]);
    await command('nft', ['--check', '-f', `${dir}/check.nft`]);
    return dir;
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}

async function activate(
  config: RoutingConfig,
  context: RoutingContext,
  dir: string
): Promise<void> {
  const rules = JSON.parse(
    await command('ip', ['-j', '-4', 'rule', 'show'])
  ) as Array<{ priority?: number }>;
  if (
    rules.some(
      (rule) =>
        rule.priority !== undefined &&
        rule.priority >= ROUTING_POLICY_PRIORITY &&
        rule.priority <= ROUTING_POLICY_PRIORITY + 16
    )
  )
    throw new RoutingValidationError(
      'Routing policy priorities are already occupied'
    );
  const links = JSON.parse(
    await command('ip', ['-j', 'link', 'show'])
  ) as Array<{ ifname: string }>;
  if (!links.some((link) => link.ifname === context.inboundInterface))
    throw new RoutingValidationError('Project AWG interface is not running');
  const names = config.egresses.map((egress) => egressInterface(egress.id));
  if (links.some((link) => names.includes(link.ifname)))
    throw new RoutingValidationError(
      'An outbound interface already exists; refusing to replace it'
    );
  // A pre-existing table is not ours unless it belonged to current and was removed.
  const tables = JSON.parse(await command('nft', ['-j', 'list', 'tables'])) as {
    nftables?: Array<{ table?: { family: string; name: string } }>;
  };
  if (
    tables.nftables?.some(
      (entry) =>
        entry.table?.family === 'ip' && entry.table.name === ROUTING_TABLE
    )
  )
    throw new RoutingValidationError(
      'Routing nftables table is already occupied'
    );
  const owned: OwnedRuntime = {
    child: null,
    dir,
    config,
    context,
    interfaces: [],
    sourceRules: [],
    nft: false,
    tproxyRoute: false,
    tproxyRule: false,
  };
  try {
    // sing-box discovers and caches interfaces during startup. All bound TUNs
    // and their source policies must exist before creating its interface finder.
    for (const [index, egress] of config.egresses.entries()) {
      const name = egressInterface(egress.id);
      const profile = parseAwgProfile(egress.profile);
      const sourceAddress = `${profile.address.split('/')[0]}/32`;
      await command('awg-quick', ['up', `${dir}/${name}.conf`]);
      owned.interfaces.push(name);
      const table = ROUTING_POLICY_TABLE + index + 1;
      const priority = ROUTING_POLICY_PRIORITY + index + 1;
      await command('ip', [
        '-4',
        'route',
        'add',
        'default',
        'dev',
        name,
        'table',
        String(table),
      ]);
      const sourceRule = {
        address: sourceAddress,
        table,
        priority,
        route: true,
        rule: false,
      };
      owned.sourceRules.push(sourceRule);
      await command('ip', [
        '-4',
        'rule',
        'add',
        'priority',
        String(priority),
        'from',
        sourceAddress,
        'table',
        String(table),
      ]);
      sourceRule.rule = true;
    }
    // Private subprocess diagnostics never flow to application output or API responses.
    const log = await open(`${dir}/sing-box.log`, 'ax', 0o600);
    let child: ChildProcess;
    let spawnFailed = false;
    try {
      child = spawn('sing-box', ['run', '-c', `${dir}/sing-box.json`], {
        stdio: ['ignore', log.fd, log.fd],
      });
      owned.child = child;
      child.once('error', () => {
        spawnFailed = true;
      });
    } finally {
      await log.close();
    }
    await listenerReady(child);
    if (spawnFailed)
      throw new RoutingValidationError('Could not start routing process');
    await command('ip', [
      '-4',
      'route',
      'add',
      'local',
      '0.0.0.0/0',
      'dev',
      'lo',
      'table',
      String(ROUTING_POLICY_TABLE),
    ]);
    owned.tproxyRoute = true;
    await command('ip', [
      '-4',
      'rule',
      'add',
      'priority',
      String(ROUTING_POLICY_PRIORITY),
      'fwmark',
      `${ROUTING_MARK}/0xffffffff`,
      'table',
      String(ROUTING_POLICY_TABLE),
    ]);
    owned.tproxyRule = true;
    await command('nft', ['-f', `${dir}/routes.nft`]);
    owned.nft = true;
    if (child.exitCode !== null || child.signalCode !== null)
      throw new RoutingValidationError(
        'Routing process stopped during activation; fail-closed gate remains'
      );
    current = owned;
    status = {
      state: 'running',
      enabled: true,
      pid: child.pid ?? null,
      appliedAt: new Date().toISOString(),
      error: null,
    };
    child.once('exit', () => {
      if (current !== owned) return;
      // Keep interception installed on a crash: selected traffic must not silently leak to direct.
      status = {
        ...status,
        state: 'failed',
        pid: null,
        error:
          'Routing process stopped; interception remains until restart or disable',
      };
    });
  } catch (error) {
    try {
      await cleanup(owned);
    } catch (cleanupError) {
      current = owned;
      status = {
        state: 'failed',
        enabled: true,
        pid: null,
        appliedAt: null,
        error:
          'Candidate cleanup failed; scoped fail-closed gate and retry state remain',
      };
      throw cleanupError;
    }
    throw error;
  }
}

async function applyInternal(
  value: unknown,
  context: RoutingContext,
  fallback?: Snapshot
): Promise<RoutingStatus> {
  const config = validateRoutingConfig(value, context);
  if (!config.enabled) {
    await stopInternal();
    return getRoutingStatus();
  }
  const dir = await prepare(config, context);
  const previous = current
    ? { config: current.config, context: current.context }
    : (fallback ?? { config: RoutingConfigSchema.parse({}), context });
  try {
    await installGate([previous, { config, context }]);
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
  await stopInternal(false);
  try {
    await activate(config, context, dir);
    await removeGate();
    return getRoutingStatus();
  } catch {
    await stopInternal(false);
    await rm(dir, { recursive: true, force: true });
    try {
      if (previous.config.enabled) {
        const oldDir = await prepare(previous.config, previous.context);
        await activate(previous.config, previous.context, oldDir);
        await removeGate();
      } else await stopInternal();
    } catch {
      status = {
        state: 'failed',
        enabled: true,
        pid: null,
        appliedAt: null,
        error:
          'Candidate and rollback failed; scoped fail-closed gate remains until disable or repair',
      };
    }
    throw new RoutingValidationError(
      'Routing candidate failed; previous configuration was restored when possible'
    );
  }
}

export function applyRouting(
  config: RoutingConfig,
  context: RoutingContext
): Promise<RoutingStatus> {
  return serialized(() => applyInternal(config, context));
}

/** Serialize the whole API transaction, including private persistence and rollback. */
export function saveAndApplyRouting(
  config: RoutingConfig,
  context: RoutingContext,
  apply = false
): Promise<RoutingStatus> {
  return serialized(async () => {
    const validated = validateRoutingConfig(config, context);
    const previousDraft = await loadRoutingConfig();
    const previousApplied = await loadAppliedRoutingConfig();
    const previousRuntime = current
      ? { config: current.config, context: current.context }
      : null;
    if (apply)
      await applyInternal(validated, context, {
        config: previousApplied,
        context,
      });
    try {
      await saveRoutingConfig(validated);
      if (apply) await saveAppliedRoutingConfig(validated);
    } catch {
      await saveRoutingConfig(previousDraft).catch(() => {});
      if (apply) {
        await saveAppliedRoutingConfig(previousApplied).catch(() => {});
        await applyInternal(
          previousRuntime?.config ?? previousApplied,
          previousRuntime?.context ?? context,
          previousRuntime ?? { config: previousApplied, context }
        );
      }
      throw new RoutingValidationError(
        'Private routing save failed; runtime rollback was attempted'
      );
    }
    return getRoutingStatus();
  });
}

export async function startRouting(
  context: RoutingContext,
  appliedConfigPath?: string
): Promise<RoutingStatus> {
  return serialized(async () => {
    const applied = await loadAppliedRoutingConfig(appliedConfigPath);
    return applyInternal(applied, context, { config: applied, context });
  });
}
