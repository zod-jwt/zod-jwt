import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema } from '../../schema/index.js';

/**
 * Validates that the `privateKey` has the correct hash algorithm for `PS` based algorithms
 *
 * * For `PS256` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha256`
 * * For `PS384` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha384`
 * * For `PS512` the `mgf1HashAlgorithm` and `hashAlgorithm` need to equal `sha512`
 */
export const validateHashAlgorithm = (
  algorithm: JwtAlgorithmsPSSchema,
  mgf1HashAlgorithm: string | undefined,
  hashAlgorithm: string | undefined,
  privateOrPublic: 'publicKey' | 'privateKey'
) => {
  if (algorithm !== 'PS256' && algorithm !== 'PS384' && algorithm !== 'PS512') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateHashAlgorithm. The allowed algorithms are PS256, PS384, and PS512`,
    });
  }

  if (typeof mgf1HashAlgorithm !== 'string' || mgf1HashAlgorithm.length === 0) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unable to determine the mgf1HashAlgorithm of the ${privateOrPublic}`,
    });
  }

  if (typeof hashAlgorithm !== 'string' || hashAlgorithm.length === 0) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unable to determine the hashAlgorithm of the ${privateOrPublic}`,
    });
  }

  if (mgf1HashAlgorithm !== hashAlgorithm) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `The mgf1HashAlgorithm and the hashAlgorithm of your ${privateOrPublic} do not match`,
    });
  }

  const length = parseInt(algorithm.slice(-3), 10);

  if (hashAlgorithm !== `sha${length}`) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Your ${privateOrPublic} has a hashAlgorithm of ${hashAlgorithm} but expected it to be sha${length}`,
    });
  }

  return true as const;
};
