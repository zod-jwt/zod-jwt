import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAsymmetricAlgorithmsSchema, JwtSymmetricAlgorithmsSchema } from '../../schema/index.js';
import { getTestCredentials } from '../../tests/test-helper-get-credentials.js';
import { validatePublicKeyMaterial } from '../index.js';

describe('validatePublicKeyMaterial', () => {
  it('should exist', () => {
    expect(validatePublicKeyMaterial).toBeTruthy();
  });

  test.each([
    // rsa
    'RS256',
    'RS384',
    'RS512',
    // rsa-pss
    'PS256',
    'PS384',
    'PS512',
    // ec
    'ES256',
    'ES384',
    'ES512',
  ] satisfies JwtAsymmetricAlgorithmsSchema[])('%s: should accept a well formed publicKey', (algorithm) => {
    // @ts-expect-error overloading
    const { publicKey } = getTestCredentials(algorithm);
    expect(
      validatePublicKeyMaterial({
        algorithm,
        publicKey,
      })
    ).toEqual(true);
  });

  // Validating the publicKey against mismatches doesn't make sense.
  // There isn't enough info on the publicKeys to determine what algorithm they necessarily belong to
  // Only testing the validity of the acceptance case and not testing the rejection case makes sense here

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])('%s: should reject against symmetric algorithm', (algorithm) => {
    expect(() => {
      const { secret } = getTestCredentials(algorithm, 'valid', 'hex');
      validatePublicKeyMaterial({
        algorithm: algorithm as unknown as JwtAsymmetricAlgorithmsSchema,
        publicKey: secret,
      });
    }).toThrow(JwtProviderInvalidKeyMaterialError);
  });
});
