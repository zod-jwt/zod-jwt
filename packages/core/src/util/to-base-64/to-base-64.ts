import base64url from 'base64url';
import { Base64Encoded, Base64UrlEncoded } from '../../schema/index.js';

/**
 * Takes a base64UrlEncoded string and converts it to base64Url
 */
export function toBase64(string: Base64UrlEncoded): Base64Encoded {
  return base64url.default.toBase64(string) as Base64Encoded;
}
