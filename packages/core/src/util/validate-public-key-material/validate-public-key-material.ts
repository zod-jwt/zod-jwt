import { createPublicKey } from 'node:crypto';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import {
  JwtAlgorithmsESSchema,
  JwtAlgorithmsPSSchema,
  JwtAlgorithmsRSSchema,
  JwtAsymmetricAlgorithmTypesSchema,
  JwtAsymmetricAlgorithmsSchema,
} from '../../schema/index.js';
import { validateCurve } from '../validate-curve/validate-curve.js';
import { validateKeyType } from '../validate-key-type/validate-key-type.js';
import { validateModulusLength } from '../validate-modulus-length/validate-modulus-length.js';

/**
 * Checks if a string is valid `publicKey` material
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
 * For `ES` algorithms it checks the curve is correct
 * * `prime256v1` for `ES256`
 * * `secp384r1` for `ES384`
 * * `secp521r1` for `ES512`
 *
 * ---
 *
 * Provide the `publicKey`, not the `privateKey` when calling this function
 */
export function validatePublicKeyMaterial({ publicKey: privateKey, algorithm }: { publicKey: string; algorithm: JwtAsymmetricAlgorithmsSchema }) {
  let algorithmType: JwtAsymmetricAlgorithmTypesSchema;
  if (algorithm === 'RS256' || algorithm === 'RS384' || algorithm === 'RS512') {
    algorithmType = 'RS';
  } else if (algorithm === 'PS256' || algorithm === 'PS384' || algorithm === 'PS512') {
    algorithmType = 'PS';
  } else if (algorithm === 'ES256' || algorithm === 'ES384' || algorithm === 'ES512') {
    algorithmType = 'ES';
  } else {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An unknown algorithm type was passed to validatePublicKeyMaterial: ${algorithm}`,
    });
  }
  try {
    const { type, asymmetricKeyType, asymmetricKeyDetails } = createPublicKey(privateKey);
    if (type === 'private') {
      throw new JwtProviderInvalidKeyMaterialError({
        message: 'The privateKey was passed as the publicKey when checking the validity of the publicKey',
      });
    } else if (type === 'secret') {
      throw new JwtProviderInvalidKeyMaterialError({ message: 'A secret was passed as the publicKey when checking the validity of the publicKey' });
    } else if (type === 'public') {
      if (!asymmetricKeyDetails) {
        throw new JwtProviderInvalidKeyMaterialError({
          message: `Unable to get the asymmetricKeyDetails from your publicKey`,
        });
      }
      const { modulusLength, namedCurve } = asymmetricKeyDetails;
      validateKeyType(algorithm, asymmetricKeyType, 'publicKey');

      if (algorithmType === 'RS') {
        validateModulusLength(algorithm as JwtAlgorithmsRSSchema, modulusLength, 'publicKey');
      } else if (algorithmType === 'PS') {
        validateModulusLength(algorithm as JwtAlgorithmsPSSchema, modulusLength, 'publicKey');
        // public key does not have a salt prop
        // public key does not have mgf1HashAlgorithm or hashAlgorithm props
      } else if (algorithmType === 'ES') {
        // validate curve
        validateCurve(algorithm as JwtAlgorithmsESSchema, namedCurve, 'publicKey');
      } else {
        throw new JwtProviderInvalidKeyMaterialError({
          message: `Unknown algorithm type ${algorithmType}`,
        });
      }

      return true as const;
    } else {
      throw new JwtProviderInvalidKeyMaterialError({
        message: `Unable to determine the type of the publicKey`,
      });
    }
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string') {
      if (error.code === 'ERR_OSSL_UNSUPPORTED') {
        throw new JwtProviderInvalidKeyMaterialError({ message: 'Invalid key material. Unable to inspect your publicKey' });
      } else {
        throw new JwtProviderInvalidKeyMaterialError({ error, message: `Invalid key material` });
      }
    } else if (error instanceof JwtProviderInvalidKeyMaterialError) {
      throw error;
    } else {
      throw new JwtProviderInvalidKeyMaterialError({
        message: 'An unknown error was thrown when checking the validity of your publicKey',
        error: error,
      });
    }
  }
}
