import { JwtProviderBadConfigError, JwtTokenMalformedError } from '../../errors/index.js';
import {
  IJSON,
  JwtAlgorithmsSchema,
  JwtAsymmetricAlgorithmsSchema,
  JwtHeaderSchema,
  JwtSecretEncodingSchema,
  JwtSymmetricAlgorithmsSchema,
} from '../../schema/index.js';
import { toBase64, toBase64Url, validatePrivateKeyMaterial, validatePublicKeyMaterial, validateSecretMaterial } from '../../util/index.js';
import {
  JwtProviderSignArgs,
  JwtProviderSignResponse,
  JwtProviderVerifyArgs,
  JwtProviderVerifyResponse,
} from '../jwt-abstract-provider-types/abstract-jwt-types.js';

/**
 * If you are authoring your own provider, your input props should extend this object
 */
export type JwtProviderConstructorArgs<
  ProviderName extends string,
  SupportedAlgorithms extends JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms
> = Omit<JwtAbstractProviderConstructorArgs<ProviderName, SupportedAlgorithms, EnabledAlgorithms>, 'supportedAlgorithms'>;

export type JwtAbstractProviderConstructorArgs<
  ProviderName extends string,
  SupportedAlgorithms extends JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms
> = {
  /**
   * ---
   *
   * Provider Authors:
   *
   * You need to provide a list of supported algorithms when creating your provider.
   *
   * You should not expose this to the consumer.
   *
   * ---
   *
   * This enables intellisense to work correctly and prevents consumers from passing an invalid provider/algorithm mismatch.
   */
  readonly supportedAlgorithms: SupportedAlgorithms[];
  algorithms: EnabledAlgorithms[];
  providerName: ProviderName;
};

/**
 * Build your own provider by extending this class
 *
 * All claim validation is handled by the `Jwt` class and your provider does not need to implement this feature.
 *
 * You only need to provide the following:
 * 1. An implementation of `verifySignature()`
 * 2. An implementation of `generateSignature()`
 * 3. An array of `supportedAlgorithms` in the constructor (readonly set by the provider)
 * 4. An array of `enabledAlgorithms` in the constructor (provided by the user at runtime)
 *
 * Your constructor should take in some sort of credentials so that your verify and sign functions have access to them
 *
 * You should verify that the credentials provided by the user are valid within the context of the algorithms you are implementing.
 * This abstract class has a few functions that checks to make sure that minimum security standards are enforced.
 * For symmetric algorithms, the `secret` should be validated by calling `validateSecretKey`.
 * For asymmetric algorithms the `publicKey` should be validated by calling `validatePublicKey`.
 * For asymmetric algorithms the `privateKey` should be validated by calling `validatePrivateKey` if the `privateKey` is provided.
 * For asymmetric algorithms the `privateKey` and `publicKey` should be compared to make sure they match if the `privateKey` is provided.
 */
export abstract class JwtAbstractProvider<
  ProviderName extends string,
  SupportedAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms = SupportedAlgorithms
> {
  constructor(private readonly args: JwtAbstractProviderConstructorArgs<ProviderName, SupportedAlgorithms, EnabledAlgorithms>) {}

  get supportedAlgorithms() {
    return this.args.supportedAlgorithms;
  }

  get enabledAlgorithms() {
    return this.args.algorithms;
  }

  get providerName() {
    return this.args.providerName;
  }

  /**
   * ---
   *
   * If you are creating your own provider you need to implement your signature verification strategy here.
   *
   * ---
   *
   * You will only receive an algorithm that was defined in your `supportedAlgorithms`. Additionally,
   * you will only receive an algorithm that was enabled by the end user via the `algorithms` props when
   * instantiating your provider.
   *
   * ---
   *
   * You can reject signature verification two ways:
   * * Return false - this will automatically throw `JwtTokenInvalidSignatureError` for you
   * * Throw `JwtTokenInvalidSignatureError` to customize the message
   *
   * ---
   *
   * **Claim validation is not the responsibility of this function**
   */
  public abstract _verifySignature(args: JwtProviderVerifyArgs): Promise<JwtProviderVerifyResponse>;

  /**
   * If you are creating your own provider you need to implement your signing strategy here.
   *
   * You will only receive an algorithm that was defined in your `supportedAlgorithms`.
   *
   * You should really never throw in here unless your are making api calls to a service like KMS. (Validation and configuration should be implemented in the constructor)
   *
   * If you do need to throw an error when using a service like KMS you should throw a `JwtProviderServiceExceptionError`.
   *
   * **Claim validation is not the responsibility of the provider**
   */
  public abstract _generateSignature(args: JwtProviderSignArgs): Promise<JwtProviderSignResponse>;

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method if you are creating your own provider or enhance it
   * by performing additional validation in your provider
   *
   * ---
   *
   * Validates the bitSize of the `secret` is greater than or equal to the hashing algorithm bitSize
   *
   */
  protected _validateSecretKey<Algorithm extends JwtSymmetricAlgorithmsSchema>(props: {
    secret: string;
    encoding: JwtSecretEncodingSchema;
    algorithm: Algorithm;
  }) {
    validateSecretMaterial({
      secret: props.secret,
      encoding: props.encoding,
      algorithm: props.algorithm,
    });
  }

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method or call your own if you are creating your own provider and
   * want to enhance the validation in your provider
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
  protected _validatePublicKey<Algorithm extends JwtAsymmetricAlgorithmsSchema>(props: { publicKey: string; algorithm: Algorithm }) {
    validatePublicKeyMaterial({
      algorithm: props.algorithm,
      publicKey: props.publicKey,
    });
  }

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method if you are creating your own provider or enhance it
   * by performing additional validation in your provider
   *
   * ---
   *
   * * Validates the modulus length of the `privateKey` against the hash size
   * * Validates that the `privateKey` and algorithm combination are valid (i.e. can't sign ES with RS keys)
   *
   * ---
   *
   * * Returns an object with the `privateKey` unaltered
   */
  protected _validatePrivateKey<Algorithm extends JwtAsymmetricAlgorithmsSchema>(props: { privateKey: string; algorithm: Algorithm }) {
    validatePrivateKeyMaterial({
      algorithm: props.algorithm,
      privateKey: props.privateKey,
    });
  }

  /**
   * todo: should validate if the publickey privatekey match
   * Could generate and verify a signature
   * Since this will need to be promise based it couldn't be awaited in the constructor (could still call it though)
   */
  protected _validatePrivateKeyPublicKeyMatch() {
    throw new Error('not implemented');
  }

  public _verifyAlgorithmIsEnabled(algorithm: string) {
    if (this.args.algorithms.indexOf(algorithm as EnabledAlgorithms) === -1) {
      throw new JwtProviderBadConfigError({
        message: `Algorithm ${algorithm} is not enabled. Enabled algorithms are ${this.args.algorithms.join(', ')}`,
      });
    }
    return algorithm as EnabledAlgorithms;
  }

  /**
   * If you are creating your own provider you can override this method
   *
   * Default implementation generates a set of JWT headers including the `alg` and `typ` props
   *
   */
  public _constructHeader(algorithm: EnabledAlgorithms) {
    return {
      typ: 'JWT',
      alg: algorithm,
    } as const;
  }

  public _validateHeaderSchema(data: IJSON) {
    const test = JwtHeaderSchema.safeParse(data);
    if (!test.success) {
      throw new JwtTokenMalformedError({
        message: `Error when validating the header of the JWT`,
      });
    }
    return test.data as unknown as JwtHeaderSchema<EnabledAlgorithms>;
  }

  // util helpers
  protected _toBase64 = toBase64;
  protected _toBase64Url = toBase64Url;
}
