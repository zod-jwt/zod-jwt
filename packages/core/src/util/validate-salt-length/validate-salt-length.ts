import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema } from '../../schema/index.js';

/**
 * Validates that the `saltLength` is long enough for type type of algorithm
 *
 * * `PS256` should have a `saltLength` of at least `32`
 * * `PS384` should have a `saltLength` of at least `48`
 * * `PS512` should have a `saltLength` of at least `64`
 */
export function validateSaltLength(algorithm: JwtAlgorithmsPSSchema, saltLength: number | undefined, privateOrPublic: 'privateKey' | 'publicKey') {
  if (algorithm !== 'PS256' && algorithm !== 'PS384' && algorithm !== 'PS512') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateSaltLength. The allowed algorithms are PS256, PS384, or PS512`,
    });
  }
  if (typeof saltLength !== 'number') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unable to determine the saltLength of the ${privateOrPublic}`,
    });
  }
  const length = parseInt(algorithm.slice(-3, 10));
  if (saltLength < length >> 3) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `A salt length greater than or equal to of ${
        length >> 3
      } is required to for ${algorithm} but the salt length of the ${privateOrPublic} was ${saltLength}`,
    });
  }
  return true as const;
}
