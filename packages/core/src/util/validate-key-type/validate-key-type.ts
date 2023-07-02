import { KeyType } from 'node:crypto';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAsymmetricAlgorithmsSchema } from '../../schema/index.js';

/**
 *
 * Validates that the `keyType` is valid for the algorithm
 *
 * * `RS` based algorithms should have a `keyType` of `rsa`
 * * `PS` based algorithms should have a `keyType` of `rsa-pss`
 * * `ES` based algorithms should have a `keyType` of `ec`
 */
export const validateKeyType = (
  algorithm: JwtAsymmetricAlgorithmsSchema,
  keyType: KeyType | undefined,
  privateOrPublic: 'privateKey' | 'publicKey'
) => {
  if (
    algorithm !== 'RS256' &&
    algorithm !== 'RS384' &&
    algorithm !== 'RS512' &&
    algorithm !== 'PS256' &&
    algorithm !== 'PS384' &&
    algorithm !== 'PS512' &&
    algorithm !== 'ES256' &&
    algorithm !== 'ES384' &&
    algorithm !== 'ES512'
  ) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateKeyType. The allowed algorithms are RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, or ES512`,
    });
  }

  if (keyType === undefined) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unable to determine the keyType of the ${privateOrPublic}`,
    });
  }

  if ((algorithm === 'RS256' || algorithm === 'RS384' || algorithm === 'RS512') && keyType !== 'rsa') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Invalid ${privateOrPublic}. Expected the keyType of the ${privateOrPublic} to be "rsa" but got "${keyType}"`,
    });
  }

  if (algorithm === 'PS256' || algorithm === 'PS384' || algorithm === 'PS512') {
    // PS public keys will return rsa while PS private keys will return rsa-pss when calling crypto.createPublicKey and crypto.createPrivateKey
    if (privateOrPublic === 'privateKey' && keyType !== 'rsa-pss') {
      throw new JwtProviderInvalidKeyMaterialError({
        message: `Invalid ${privateOrPublic}. Expected the keyType of the ${privateOrPublic} to be "rsa-pss" but got "${keyType}"`,
      });
    }
    if (privateOrPublic === 'publicKey' && keyType !== 'rsa') {
      throw new JwtProviderInvalidKeyMaterialError({
        message: `Invalid ${privateOrPublic}. Expected the keyType of the ${privateOrPublic} to be "rsa" but got "${keyType}"`,
      });
    }
  }

  if ((algorithm === 'ES256' || algorithm === 'ES384' || algorithm === 'ES512') && keyType !== 'ec') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Invalid ${privateOrPublic}. Expected the keyType of the ${privateOrPublic} to be "ec" but got "${keyType}"`,
    });
  }

  return true as const;
};
