import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema, JwtAlgorithmsRSSchema } from '../../schema/index.js';

/**
 *
 * Validates that the `modulusLength` is at least 2048
 */
export const validateModulusLength = (
  algorithm: JwtAlgorithmsRSSchema | JwtAlgorithmsPSSchema,
  modulusLength: number | undefined,
  privateOrPublic: 'privateKey' | 'publicKey'
) => {
  if (
    algorithm !== 'RS256' &&
    algorithm !== 'RS384' &&
    algorithm !== 'RS512' &&
    algorithm !== 'PS256' &&
    algorithm !== 'PS384' &&
    algorithm !== 'PS512'
  ) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateModulusLength. The allowed algorithms are RS256, RS384, RS512, PS256, PS384, or PS512`,
    });
  }

  if (typeof modulusLength !== 'number') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unable to determine the modulusLength of the ${privateOrPublic}`,
    });
  }
  const length = parseInt(algorithm.slice(-3, 10));
  if (modulusLength < length << 3) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `A modulus length greater than or equal to of ${
        length << 3
      } is required to for ${algorithm} but the modulus length of the ${privateOrPublic} was ${modulusLength}`,
    });
  }
  return true as const;
};
