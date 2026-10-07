import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';

/** Raw X25519 keys use the same representation as wg/awg genkey and pubkey. */
export function generatePrivateKey(): string {
  const key = randomBytes(32);
  key[0] = key[0]! & 248;
  key[31] = (key[31]! & 127) | 64;
  return key.toString('base64');
}

export function derivePublicKey(value: string): string {
  const raw = Buffer.from(value, 'base64');
  if (raw.length !== 32 || raw.toString('base64') !== value) {
    throw new Error('Invalid WireGuard private key');
  }
  // RFC 8410 PKCS#8 wrapper for a raw 32-byte X25519 private key.
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      raw,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(key)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64');
}

export function generatePreSharedKey(): string {
  return randomBytes(32).toString('base64');
}
