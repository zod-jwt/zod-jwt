import { KeyType } from 'node:crypto';
import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAsymmetricAlgorithmsSchema } from '../../schema/index.js';
import { validateKeyType } from '../index.js';

describe('validatekeyType', () => {
  it('should exist', () => {
    expect(validateKeyType).toBeTruthy();
  });

  test.each([
    // rs
    { algorithm: 'RS256', keyType: 'rsa-pss' },
    { algorithm: 'RS256', keyType: 'ec' },
    { algorithm: 'RS256', keyType: 'dsa' },
    { algorithm: 'RS256', keyType: 'ed25519' },
    { algorithm: 'RS256', keyType: 'ed448' },
    { algorithm: 'RS256', keyType: 'x25519' },
    { algorithm: 'RS256', keyType: 'x448' },

    { algorithm: 'RS384', keyType: 'rsa-pss' },
    { algorithm: 'RS384', keyType: 'ec' },
    { algorithm: 'RS384', keyType: 'dsa' },
    { algorithm: 'RS384', keyType: 'ed25519' },
    { algorithm: 'RS384', keyType: 'ed448' },
    { algorithm: 'RS384', keyType: 'x25519' },
    { algorithm: 'RS384', keyType: 'x448' },

    { algorithm: 'RS512', keyType: 'rsa-pss' },
    { algorithm: 'RS512', keyType: 'ec' },
    { algorithm: 'RS512', keyType: 'dsa' },
    { algorithm: 'RS512', keyType: 'ed25519' },
    { algorithm: 'RS512', keyType: 'ed448' },
    { algorithm: 'RS512', keyType: 'x25519' },
    { algorithm: 'RS512', keyType: 'x448' },

    // ps
    { algorithm: 'PS256', keyType: 'rsa' },
    { algorithm: 'PS256', keyType: 'ec' },
    { algorithm: 'PS256', keyType: 'dsa' },
    { algorithm: 'PS256', keyType: 'ed25519' },
    { algorithm: 'PS256', keyType: 'ed448' },
    { algorithm: 'PS256', keyType: 'x25519' },
    { algorithm: 'PS256', keyType: 'x448' },

    { algorithm: 'PS384', keyType: 'rsa' },
    { algorithm: 'PS384', keyType: 'ec' },
    { algorithm: 'PS384', keyType: 'dsa' },
    { algorithm: 'PS384', keyType: 'ed25519' },
    { algorithm: 'PS384', keyType: 'ed448' },
    { algorithm: 'PS384', keyType: 'x25519' },
    { algorithm: 'PS384', keyType: 'x448' },

    { algorithm: 'PS512', keyType: 'rsa' },
    { algorithm: 'PS512', keyType: 'ec' },
    { algorithm: 'PS512', keyType: 'dsa' },
    { algorithm: 'PS512', keyType: 'ed25519' },
    { algorithm: 'PS512', keyType: 'ed448' },
    { algorithm: 'PS512', keyType: 'x25519' },
    { algorithm: 'PS512', keyType: 'x448' },

    // es
    { algorithm: 'ES256', keyType: 'rsa' },
    { algorithm: 'ES256', keyType: 'rsa-pss' },
    { algorithm: 'ES256', keyType: 'dsa' },
    { algorithm: 'ES256', keyType: 'ed25519' },
    { algorithm: 'ES256', keyType: 'ed448' },
    { algorithm: 'ES256', keyType: 'x25519' },
    { algorithm: 'ES256', keyType: 'x448' },

    { algorithm: 'ES384', keyType: 'rsa' },
    { algorithm: 'ES384', keyType: 'rsa-pss' },
    { algorithm: 'ES384', keyType: 'dsa' },
    { algorithm: 'ES384', keyType: 'ed25519' },
    { algorithm: 'ES384', keyType: 'ed448' },
    { algorithm: 'ES384', keyType: 'x25519' },
    { algorithm: 'ES384', keyType: 'x448' },

    { algorithm: 'ES512', keyType: 'rsa' },
    { algorithm: 'ES512', keyType: 'rsa-pss' },
    { algorithm: 'ES512', keyType: 'dsa' },
    { algorithm: 'ES512', keyType: 'ed25519' },
    { algorithm: 'ES512', keyType: 'ed448' },
    { algorithm: 'ES512', keyType: 'x25519' },
    { algorithm: 'ES512', keyType: 'x448' },
  ] satisfies { algorithm: JwtAsymmetricAlgorithmsSchema; keyType: KeyType }[])(
    '$algorithm rejects wrong keyType of $keyType',
    ({ algorithm, keyType }) => {
      expect(() => {
        validateKeyType(algorithm, keyType, 'privateKey');
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each([
    // rs
    { algorithm: 'RS256', keyType: 'rsa' },
    { algorithm: 'RS384', keyType: 'rsa' },
    { algorithm: 'RS512', keyType: 'rsa' },
    // ps
    { algorithm: 'PS256', keyType: 'rsa-pss' },
    { algorithm: 'PS384', keyType: 'rsa-pss' },
    { algorithm: 'PS512', keyType: 'rsa-pss' },
    // es
    { algorithm: 'ES256', keyType: 'ec' },
    { algorithm: 'ES384', keyType: 'ec' },
    { algorithm: 'ES512', keyType: 'ec' },
  ] satisfies { algorithm: JwtAsymmetricAlgorithmsSchema; keyType: KeyType }[])(
    '$algorithm accepts correct keyType of $keyType',
    ({ algorithm, keyType }) => {
      expect(() => {
        validateKeyType(algorithm, keyType, 'privateKey');
      }).not.toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );
});
