import { z } from 'zod';

export const JwtAlgorithmRSTypeSchema = z.literal('RS');
export type JwtAlgorithmRSTypeSchema = z.infer<typeof JwtAlgorithmRSTypeSchema>;

export const JwtAlgorithmPSTypeSchema = z.literal('PS');
export type JwtAlgorithmPSTypeSchema = z.infer<typeof JwtAlgorithmPSTypeSchema>;

export const JwtAlgorithmESTypeSchema = z.literal('ES');
export type JwtAlgorithmESTypeSchema = z.infer<typeof JwtAlgorithmESTypeSchema>;

export const JwtAlgorithmHSTypeSchema = z.literal('HS');
export type JwtAlgorithmHSTypeSchema = z.infer<typeof JwtAlgorithmHSTypeSchema>;

export const JwtAsymmetricAlgorithmTypesSchema = z.union([
  // prettier-ignore
  JwtAlgorithmRSTypeSchema,
  JwtAlgorithmPSTypeSchema,
  JwtAlgorithmESTypeSchema,
]);
export type JwtAsymmetricAlgorithmTypesSchema = z.infer<typeof JwtAsymmetricAlgorithmTypesSchema>;

export const JwtSymmetricAlgorithmTypesSchema = JwtAlgorithmHSTypeSchema;
export type JwtSymmetricAlgorithmTypesSchema = z.infer<typeof JwtSymmetricAlgorithmTypesSchema>;

export const JwtAlgorithmTypesSchema = z.union([
  // prettier-ignore
  JwtAsymmetricAlgorithmTypesSchema,
  JwtSymmetricAlgorithmTypesSchema,
]);

// KMS - RSA
export const JwtAlgorithmRS256Schema = z.literal('RS256');
export type JwtAlgorithmRS256Schema = z.infer<typeof JwtAlgorithmRS256Schema>;

export const JwtAlgorithmRS384Schema = z.literal('RS384');
export type JwtAlgorithmRS384Schema = z.infer<typeof JwtAlgorithmRS384Schema>;

export const JwtAlgorithmRS512Schema = z.literal('RS512');
export type JwtAlgorithmRS512Schema = z.infer<typeof JwtAlgorithmRS512Schema>;

export const JwtAlgorithmsRSSchema = z.union([
  // prettier-ignore
  JwtAlgorithmRS256Schema,
  JwtAlgorithmRS384Schema,
  JwtAlgorithmRS512Schema,
]);
/**
 * All `RS` based algorithms
 */
export type JwtAlgorithmsRSSchema = z.infer<typeof JwtAlgorithmsRSSchema>;

// KMS - RSA
export const JwtAlgorithmPS256Schema = z.literal('PS256');
export type JwtAlgorithmPS256Schema = z.infer<typeof JwtAlgorithmPS256Schema>;

export const JwtAlgorithmPS384Schema = z.literal('PS384');
export type JwtAlgorithmPS384Schema = z.infer<typeof JwtAlgorithmPS384Schema>;

export const JwtAlgorithmPS512Schema = z.literal('PS512');
export type JwtAlgorithmPS512Schema = z.infer<typeof JwtAlgorithmPS512Schema>;

export const JwtAlgorithmsPSSchema = z.union([
  // prettier-ignore
  JwtAlgorithmPS256Schema,
  JwtAlgorithmPS384Schema,
  JwtAlgorithmPS512Schema,
]);
/**
 * All `PS` based algorithms
 */
export type JwtAlgorithmsPSSchema = z.infer<typeof JwtAlgorithmsPSSchema>;

// KMS - ECC_NIST (specific)
export const JwtAlgorithmES256Schema = z.literal('ES256');
export type JwtAlgorithmES256Schema = z.infer<typeof JwtAlgorithmES256Schema>;

export const JwtAlgorithmES384Schema = z.literal('ES384');
export type JwtAlgorithmES384Schema = z.infer<typeof JwtAlgorithmES384Schema>;

export const JwtAlgorithmES512Schema = z.literal('ES512');
export type JwtAlgorithmES512Schema = z.infer<typeof JwtAlgorithmES512Schema>;

export const JwtAlgorithmsESSchema = z.union([
  // prettier-ignore
  JwtAlgorithmES256Schema,
  JwtAlgorithmES384Schema,
  JwtAlgorithmES512Schema,
]);
/**
 * All `ES` based algorithms
 */
export type JwtAlgorithmsESSchema = z.infer<typeof JwtAlgorithmsESSchema>;

// KMS - MAC (specific)
export const JwtAlgorithmHS256Schema = z.literal('HS256');
export type JwtAlgorithmHS256Schema = z.inferFlattenedErrors<typeof JwtAlgorithmHS256Schema>;

export const JwtAlgorithmHS384Schema = z.literal('HS384');
export type JwtAlgorithmHS384Schema = z.infer<typeof JwtAlgorithmHS384Schema>;

export const JwtAlgorithmHS512Schema = z.literal('HS512');
export type JwtAlgorithmHS512Schema = z.infer<typeof JwtAlgorithmHS512Schema>;

export const JwtAlgorithmsHSSchema = z.union([
  // prettier-ignore
  JwtAlgorithmHS256Schema,
  JwtAlgorithmHS384Schema,
  JwtAlgorithmHS512Schema,
]);
/**
 * All `HS` based algorithms
 */
export type JwtAlgorithmsHSSchema = z.infer<typeof JwtAlgorithmsHSSchema>;

export const JwtSymmetricAlgorithmsSchema = JwtAlgorithmsHSSchema;
/**
 * All symmetric based algorithms
 */
export type JwtSymmetricAlgorithmsSchema = z.infer<typeof JwtSymmetricAlgorithmsSchema>;

export const JwtAsymmetricAlgorithmsSchema = z.union([
  // prettier-ignore
  JwtAlgorithmsRSSchema,
  JwtAlgorithmsPSSchema,
  JwtAlgorithmsESSchema,
]);
/**
 * All asymmetric based algorithms
 */
export type JwtAsymmetricAlgorithmsSchema = z.infer<typeof JwtAsymmetricAlgorithmsSchema>;

export const JwtAlgorithmsSchema = z.union([
  // prettier-ignore
  JwtSymmetricAlgorithmsSchema,
  JwtAsymmetricAlgorithmsSchema,
]);

/**
 * All algorithms
 */
export type JwtAlgorithmsSchema = z.infer<typeof JwtAlgorithmsSchema>;

export const JwtSecretSchema = z.string();
/**
 * The secret value for symmetric based algorithms (HS256, HS384, HS512).
 * 
 * It must have a bit length greater than or equal to your signing algorithm.
 * 
 * You must also provide the type of encoding that your string is in. This is either
 * base64 encoding or hex encoding.
 * 
 * ---
 * 
 * To generate a secure secret use one of the following commands based on the value you provide to encoding:
 * ```bash
# For HS256 (32 bytes aka 256 bits)
openssl rand -hex 32
openssl rand -base64 32
# For HS384 (48 bytes aka 384 bits)
openssl rand -hex 48
openssl rand -base64 48
# For HS512 (64 bytes aka 512 bits)
openssl rand -hex 64
openssl rand -base64 64
 * ```
 */
export type JwtSecretSchema = z.infer<typeof JwtSecretSchema>;

export const JwtBase64SecretEncodingSchema = z.literal('base64');
export type JwtBase64SecretEncodingSchema = z.infer<typeof JwtBase64SecretEncodingSchema>;

export const JwtHexSecretEncodingSchema = z.literal('hex');
export type JwtHexSecretEncodingSchema = z.infer<typeof JwtHexSecretEncodingSchema>;

export const JwtSecretEncodingSchema = z.union([
  // prettier-ignore
  JwtBase64SecretEncodingSchema,
  JwtHexSecretEncodingSchema,
]);

export type JwtSecretEncodingSchema = z.infer<typeof JwtSecretEncodingSchema>;
