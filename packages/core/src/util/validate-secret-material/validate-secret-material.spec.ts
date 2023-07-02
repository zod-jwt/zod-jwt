import { randomBytes } from 'node:crypto';
import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAsymmetricAlgorithmsSchema, JwtSymmetricAlgorithmsSchema } from '../../schema/index.js';
import { getTestCredentials } from '../../tests/test-helper-get-credentials.js';
import { validateSecretMaterial } from '../index.js';

describe('validateSecretMaterial', () => {
  const generateSecret = (algorithm: JwtSymmetricAlgorithmsSchema, encoding: 'base64' | 'hex', type: 'valid' | 'invalid') => {
    const length = parseInt(algorithm.slice(2)) / 8 - (type === 'invalid' ? 1 : 0);

    return randomBytes(length).toString(encoding);
  };

  it('should exist', () => {
    expect(validateSecretMaterial).toBeTruthy();
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])('%s: should validate a valid base64 secret', (algorithm) => {
    const secret = generateSecret(algorithm, 'base64', 'valid');
    expect(
      validateSecretMaterial({
        algorithm,
        encoding: 'base64',
        secret,
      })
    ).toEqual(true);
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])('%s: should validate a valid hex secret', (algorithm) => {
    const secret = generateSecret(algorithm, 'hex', 'valid');
    expect(
      validateSecretMaterial({
        algorithm,
        encoding: 'hex',
        secret,
      })
    ).toEqual(true);
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])(
    '%s: should throw against an invalid base64 secret',
    (algorithm) => {
      const secret = generateSecret(algorithm, 'base64', 'invalid');
      expect(() => {
        validateSecretMaterial({
          algorithm,
          encoding: 'base64',
          secret,
        });
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])('%s: should throw against invalid hex secret', (algorithm) => {
    const secret = generateSecret(algorithm, 'hex', 'invalid');
    expect(() => {
      validateSecretMaterial({
        algorithm,
        encoding: 'hex',
        secret,
      });
    }).toThrow(JwtProviderInvalidKeyMaterialError);
  });

  test.each(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] satisfies JwtAsymmetricAlgorithmsSchema[])(
    '%s: should thrown against invalid algorithms',
    (_algorithm) => {
      expect(() => {
        // intentional cast
        const algorithm = _algorithm as unknown as JwtSymmetricAlgorithmsSchema;
        const secret = generateSecret(algorithm, 'hex', 'valid');
        validateSecretMaterial({
          algorithm: algorithm,
          encoding: 'hex',
          secret,
        });
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'] satisfies JwtAsymmetricAlgorithmsSchema[])(
    '%s: should reject against symmetric algorithm',
    (algorithm) => {
      expect(() => {
        // @ts-expect-error overloading
        const { privateKey } = getTestCredentials(algorithm);
        validateSecretMaterial({
          algorithm: algorithm as unknown as JwtSymmetricAlgorithmsSchema,
          secret: privateKey,
          encoding: 'base64',
        });
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );
});
