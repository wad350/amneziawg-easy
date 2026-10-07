import { describe, expect, it } from 'vitest';

import {
  derivePublicKey,
  generatePrivateKey,
  generatePreSharedKey,
} from '../../server/utils/wireguardKeys';

describe('WireGuard key generation', () => {
  it('matches the RFC 7748 X25519 basepoint test vector', () => {
    const privateKey = Buffer.from(
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      'hex'
    ).toString('base64');
    expect(
      Buffer.from(derivePublicKey(privateKey), 'base64').toString('hex')
    ).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  });
  it('creates independent clamped private keys and correctly sized PSKs', () => {
    const keys = Array.from({ length: 16 }, generatePrivateKey);
    expect(new Set(keys).size).toBe(keys.length);
    for (const encoded of keys) {
      const key = Buffer.from(encoded, 'base64');
      expect(key.length).toBe(32);
      expect(key[0]! & 7).toBe(0);
      expect(key[31]! & 128).toBe(0);
      expect(key[31]! & 64).toBe(64);
      expect(Buffer.from(derivePublicKey(encoded), 'base64').length).toBe(32);
    }
    expect(Buffer.from(generatePreSharedKey(), 'base64').length).toBe(32);
  });
  it('refuses malformed key input without echoing it into errors', () => {
    expect(() => derivePublicKey('not-a-key')).toThrow(
      'Invalid WireGuard private key'
    );
  });
});
