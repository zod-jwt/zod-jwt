import { createPrivateKey } from 'node:crypto';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import {
  JwtAlgorithmsESSchema,
  JwtAlgorithmsPSSchema,
  JwtAlgorithmsRSSchema,
  JwtAsymmetricAlgorithmTypesSchema,
  JwtAsymmetricAlgorithmsSchema,
} from '../../schema/index.js';
import { validateCurve } from '../validate-curve/validate-curve.js';
import { validateHashAlgorithm } from '../validate-hash-algorithm/validate-hash-algorithm.js';
import { validateKeyType } from '../validate-key-type/validate-key-type.js';
import { validateModulusLength } from '../validate-modulus-length/validate-modulus-length.js';
import { validateSaltLength } from '../validate-salt-length/validate-salt-length.js';

/**
 * Checks if a string is valid `privateKey` material
 *
 * ---
 *
 * Validates that the `modulusLength` is long enough for type type of algorithm
 *
 * * `RS256` and `PS256` should have a `modulusLength` of at least `2048`
 * * `RS384` and `PS384` should have a `modulusLength` of at least `3072`
 * * `RS512` and `PS512` should have a `modulusLength` of at least `4096`
 *
 * ---
 *
 * Validates that the `saltLength` is long enough for type type of algorithm
 *
 * * `PS256` should have a `saltLength` of at least `32`
 * * `PS384` should have a `saltLength` of at least `48`
 * * `PS512` should have a `saltLength` of at least `64`
 *
 * ---
 *
 * Validates that the `privateKey` has the correct hash algorithm for `PS` based algorithms
 *
 * * For `PS256` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha256`
 * * For `PS384` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha384`
 * * For `PS512` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha512`
 *
 * ---
 *
 * For `ES` algorithms it checks the curve is correct
 * * `prime256v1` for `ES256`
 * * `secp384r1` for `ES384`
 * * `secp521r1` for `ES512`
 *
 * ---
 * Provide the `privateKey`, not the `publicKey` when calling this function
 */
export function validatePrivateKeyMaterial({ privateKey, algorithm }: { privateKey: string; algorithm: JwtAsymmetricAlgorithmsSchema }) {
  let algorithmType: JwtAsymmetricAlgorithmTypesSchema;
  if (algorithm === 'RS256' || algorithm === 'RS384' || algorithm === 'RS512') {
    algorithmType = 'RS';
  } else if (algorithm === 'PS256' || algorithm === 'PS384' || algorithm === 'PS512') {
    algorithmType = 'PS';
  } else if (algorithm === 'ES256' || algorithm === 'ES384' || algorithm === 'ES512') {
    algorithmType = 'ES';
  } else {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An unknown algorithm was passed to validatePrivateKeyMaterial: ${algorithm}`,
    });
  }
  try {
    const { type, asymmetricKeyType, asymmetricKeyDetails } = createPrivateKey(privateKey);
    if (type === 'public') {
      throw new JwtProviderInvalidKeyMaterialError({
        message: 'The publicKey was passed as the privateKey when checking the validity of the privateKey',
      });
    } else if (type === 'secret') {
      throw new JwtProviderInvalidKeyMaterialError({ message: 'A secret was passed as the privateKey when checking the validity of the privateKey' });
    } else if (type === 'private') {
      if (!asymmetricKeyDetails) {
        throw new JwtProviderInvalidKeyMaterialError({
          message: `Unable to get the asymmetricKeyDetails from your privateKey`,
        });
      }
      const { hashAlgorithm, mgf1HashAlgorithm, modulusLength, namedCurve, saltLength } = asymmetricKeyDetails;
      validateKeyType(algorithm, asymmetricKeyType, 'privateKey');

      if (algorithmType === 'RS') {
        validateModulusLength(algorithm as JwtAlgorithmsRSSchema, modulusLength, 'privateKey');
      } else if (algorithmType === 'PS') {
        validateModulusLength(algorithm as JwtAlgorithmsPSSchema, modulusLength, 'privateKey');
        validateSaltLength(algorithm as JwtAlgorithmsPSSchema, saltLength, 'privateKey');
        validateHashAlgorithm(algorithm as JwtAlgorithmsPSSchema, mgf1HashAlgorithm, hashAlgorithm, 'privateKey');
      } else if (algorithmType === 'ES') {
        // validate curve
        validateCurve(algorithm as JwtAlgorithmsESSchema, namedCurve, 'privateKey');
      } else {
        throw new JwtProviderInvalidKeyMaterialError({
          message: `Unknown algorithm type ${algorithmType} was passed to validatePrivateKeyMaterial: ${algorithmType}`,
        });
      }
    }
    return true as const;
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string') {
      if (error.code === 'ERR_OSSL_UNSUPPORTED') {
        throw new JwtProviderInvalidKeyMaterialError({ message: 'Invalid key material. Unable to inspect your privateKey' });
      } else {
        throw new JwtProviderInvalidKeyMaterialError({ error, message: `Invalid key material` });
      }
    } else if (error instanceof JwtProviderInvalidKeyMaterialError) {
      throw error;
    } else {
      throw new JwtProviderInvalidKeyMaterialError({
        message: 'An unknown error was thrown when checking the validity of your privateKey',
        error: error,
      });
    }
  }
}
