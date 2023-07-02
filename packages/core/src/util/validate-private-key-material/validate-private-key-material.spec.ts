import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAsymmetricAlgorithmsSchema, JwtSymmetricAlgorithmsSchema } from '../../schema/index.js';
import { getTestCredentials } from '../../tests/test-helper-get-credentials.js';
import { validatePrivateKeyMaterial } from '../index.js';

describe('validatePrivateKeyMaterial', () => {
  it('should exist', () => {
    expect(validatePrivateKeyMaterial).toBeTruthy();
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
  ] satisfies JwtAsymmetricAlgorithmsSchema[])('%s: should accept a well formed privateKey', (algorithm) => {
    // @ts-expect-error overloading
    const { privateKey } = getTestCredentials(algorithm);
    expect(
      validatePrivateKeyMaterial({
        algorithm,
        privateKey,
      })
    ).toEqual(true);
  });

  type TestAlgMismatch = [JwtAsymmetricAlgorithmsSchema, JwtAsymmetricAlgorithmsSchema[]];

  describe.each([
    // prettier-ignore
    [
      // prettier-ignore
      'RS256',
      // rs can sign and verify smaller rs algorithms
      // the test certs take this into account and these should fail (RS384 and RS512 should fail against the RS256 cert)
      ['RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']
    ],
    [
      // prettier-ignore
      'RS384',
      // rs can sign and verify smaller rs algorithms
      // the test certs take this into account and these should fail (RS512 should fail against the RS384 cert)
      ['RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'],
    ],
    [
      // prettier-ignore
      'RS512',
      // rs can sign and verify smaller rs algorithms
      // all rs should pass with the RS512 cert
      ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'],
    ],

    [
      // prettier-ignore
      'PS256',
      // hash algorithm must match and other ps algorithms are not interchangeable
      ['PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
    ],
    [
      // prettier-ignore
      'PS384',
      // hash algorithm must match and other ps algorithms are not interchangeable
      ['PS256', 'PS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
    ],
    [
      // prettier-ignore
      'PS512',
      // hash algorithm must match and other ps algorithms are not interchangeable
      ['PS256', 'PS384', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
    ],

    [
      // prettier-ignore
      'ES256',
      // curve must match and other es algorithms are not interchangeable
      ['ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    ],
    [
      // prettier-ignore
      'ES384',
      // curve must match and other es algorithms are not interchangeable
      ['ES256', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    ],
    [
      // prettier-ignore
      'ES512',
      // curve must match and other es algorithms are not interchangeable
      ['ES256', 'ES384', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    ],
  ] satisfies TestAlgMismatch[])('should reject key alg mismatch %s: ', (algToTest, badAlgArray) => {
    // @ts-expect-error overloading
    const { privateKey } = getTestCredentials(algToTest, 'valid');

    badAlgArray.forEach((badAlg) => {
      test(`${badAlg}`, () => {
        expect(() => {
          validatePrivateKeyMaterial({
            algorithm: badAlg,
            privateKey,
          });
        }).toThrow(JwtProviderInvalidKeyMaterialError);
      });
    });
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtSymmetricAlgorithmsSchema[])('should reject against symmetric algorithm: %s', (algorithm) => {
    expect(() => {
      const { secret } = getTestCredentials(algorithm, 'valid', 'hex');
      validatePrivateKeyMaterial({
        algorithm: algorithm as unknown as JwtAsymmetricAlgorithmsSchema,
        privateKey: secret,
      });
    }).toThrow(JwtProviderInvalidKeyMaterialError);
  });
});
