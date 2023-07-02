import { Base64Encoded, Base64UrlEncoded } from '../../schema/index.js';

/**
 * Takes in two signatures and checks to make sure they match
 *
 * This is intentionally broken out to make sure that a `base64Encoded` string is not compared to a `base64UrlEncoded` string
 */
export function signatureMatches(sig1: Base64Encoded, sig2: Base64Encoded): boolean;
export function signatureMatches(sig1: Base64UrlEncoded, sig2: Base64UrlEncoded): boolean;
export function signatureMatches(sig1: Base64UrlEncoded | Base64Encoded, sig2: Base64UrlEncoded | Base64Encoded) {
  return sig1 === sig2;
}
