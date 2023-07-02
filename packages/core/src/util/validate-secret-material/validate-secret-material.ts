import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtSymmetricAlgorithmsSchema } from '../../schema/index.js';

/**
 * Checks the secret provided for symmetric algorithms meets the minimum bit requirements
 *
 * You should expose the `secret` and `encoding` to consumers of your provider so that they can explicitly set the values
 *
 * If the minimum `keySize` is not met, it will throw a `JwtProviderInvalidKeyMaterialError`
 *
 */
export const validateSecretMaterial = ({
  secret,
  encoding,
  algorithm,
}: {
  secret: string;
  encoding: 'base64' | 'hex';
  algorithm: JwtSymmetricAlgorithmsSchema;
}) => {
  if (algorithm !== 'HS256' && algorithm !== 'HS384' && algorithm !== 'HS512') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An invalid algorithm was passed to validateSecretMaterial. Received ${algorithm} but expected one of HS256, HS384, or HS512`,
    });
  }

  if (typeof secret !== 'string' || secret.length === 0) {
    throw new JwtProviderInvalidKeyMaterialError({ message: `No secret value was passed to validateSecretMaterial. Expected a string` });
  }

  if (encoding !== 'base64' && encoding !== 'hex') {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `An encoding value of ${encoding} was passed to validateSecretMaterial. Expected literal string value of "base64" or "hex"`,
    });
  }

  const algorithmTest = JwtSymmetricAlgorithmsSchema.safeParse(algorithm);

  if (!algorithmTest.success) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `Unknown algorithm was passed to validateSecretMaterial. Expected one of (${JwtSymmetricAlgorithmsSchema._def.options.join(
        ', '
      )}). Received ${algorithm}`,
    });
  }

  const keySize = Buffer.from(secret, encoding).byteLength;

  const algSize = parseInt(algorithm.slice(-3), 10);

  if (algSize > keySize << 3) {
    throw new JwtProviderInvalidKeyMaterialError({
      message: `
      The keySize of your secret must be greater than or equal to the size of the hashing algorithm.
      
      The secret keySize was ${keySize << 3} bits. The ${algorithm} requires a keySize of ${algSize} bits.
      
      Make sure your secret is of the correct encoding. The allowed encoding types are base64 or hex.
      `,
    });
  }

  return true as const;
};
