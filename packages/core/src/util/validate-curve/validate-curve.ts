import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsESSchema } from '../../schema/index.js';
/**
 * For `ES` algorithms it checks the curve is correct
 * * `prime256v1` for `ES256`
 * * `secp384r1` for `ES384`
 * * `secp521r1` for `ES512`
 */
export const validateCurve = (algorithm: JwtAlgorithmsESSchema, curve: string | undefined, privateOrPublic: 'privateKey' | 'publicKey') => {
  if (algorithm !== 'ES256' && algorithm !== 'ES384' && algorithm !== 'ES512') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateCurve. The allowed algorithms are ES256, ES384, and ES512`,
    });
  }

  if (curve === undefined || curve.length === 0) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Could not determine the curve of your ${privateOrPublic}`,
    });
  }

  if (algorithm === 'ES256' && curve !== 'prime256v1') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Invalid curve. Expected "prime256v1" but received ${curve}`,
    });
  }

  if (algorithm === 'ES384' && curve !== 'secp384r1') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Invalid curve. Expected "secp384r1" but received ${curve}`,
    });
  }

  if (algorithm === 'ES512' && curve !== 'secp521r1') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Invalid curve. Expected "secp521r1" but received ${curve}`,
    });
  }

  return true as const;
};
