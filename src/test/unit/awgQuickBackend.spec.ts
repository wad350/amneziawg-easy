import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test } from 'vitest';

const run = promisify(execFile);
const patch = fileURLToPath(
  new URL('../../../scripts/force-userspace.mjs', import.meta.url)
);
const temporary: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporary.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))
  );
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'awg-quick-backend-'));
  temporary.push(directory);
  const path = join(directory, 'awg-quick.bash');
  await writeFile(
    path,
    `#!/bin/bash
set -e
INTERFACE=wg0
die() { printf '%s\\n' "$*" >&2; exit 1; }
cmd() {
  printf '%s\\n' "$*"
  if [[ $1 == ip && \${FIXTURE_KERNEL_FAILURE:-false} == true ]]; then return 7; fi
}
add_if() {
\tlocal ret
  printf 'unsafe-original-fallback\\n'
}
add_if
`
  );
  await run(process.execPath, [patch, path]);
  // Redirect only the module-availability fixture to a temporary directory.
  // Interface operations are mocked by cmd; no ip or VPN binary is executed.
  const module = join(directory, 'module');
  await mkdir(module);
  await writeFile(
    path,
    (await readFile(path, 'utf8')).replace('/sys/module/amneziawg', module)
  );
  return { path, module };
}

describe('pinned awg-quick backend patch', () => {
  test('default and explicit userspace start Go without a kernel attempt', async () => {
    const { path } = await fixture();
    for (const backend of ['', 'userspace']) {
      const result = await run('bash', [path], {
        env: {
          ...process.env,
          AWG_BACKEND: backend,
          AWG_FORCE_USERSPACE: 'true',
        },
      });
      expect(result.stdout.trim()).toBe('amneziawg-go wg0');
    }
  });
  test('explicit kernel creates an AmneziaWG link despite the legacy Go flag', async () => {
    const { path } = await fixture();
    const result = await run('bash', [path], {
      env: {
        ...process.env,
        AWG_BACKEND: 'kernel',
        AWG_FORCE_USERSPACE: 'true',
      },
    });
    expect(result.stdout.trim()).toBe('ip link add wg0 type amneziawg');
  });
  test('kernel creation failure is returned without invoking Go or the upstream fallback', async () => {
    const { path } = await fixture();
    await expect(
      run('bash', [path], {
        env: {
          ...process.env,
          AWG_BACKEND: 'kernel',
          FIXTURE_KERNEL_FAILURE: 'true',
        },
      })
    ).rejects.toMatchObject({
      code: 7,
      stdout: 'ip link add wg0 type amneziawg\n',
    });
  });
  test('missing module fails before any interface implementation is started', async () => {
    const { path, module } = await fixture();
    await rm(module, { recursive: true });
    await expect(
      run('bash', [path], {
        env: { ...process.env, AWG_BACKEND: 'kernel' },
      })
    ).rejects.toMatchObject({
      code: 1,
      stdout: '',
      stderr: 'Kernel AWG requires an already loaded amneziawg module\n',
    });
  });
  test('unknown backend fails without invoking either implementation', async () => {
    const { path } = await fixture();
    await expect(
      run('bash', [path], {
        env: { ...process.env, AWG_BACKEND: 'auto' },
      })
    ).rejects.toMatchObject({ code: 1, stdout: '' });
  });
});
