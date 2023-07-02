import base64url from 'base64url';
import { Base64Encoded, Base64UrlEncoded, JsonString } from '../../schema/index.js';

/**
 * Takes in a branded `JsonString` and converts it to a branded `Base64UrlEncoded` string
 *
 * This should be used for example after a `JSON.stringify({})` call
 *
 * `utf8` is automatically passed as the encoding
 */
export function toBase64Url(string: JsonString, encoding: 'utf8'): Base64UrlEncoded;
/**
 * Takes in a branded `Base64Encoded` string and converts it to a branded `Base64UrlEncoded` string
 *
 * This should be used for example after calling the hmac function to generate a signature since it returns a base64 string
 *
 * `base64` is passed as the encoding
 */
export function toBase64Url(string: Base64Encoded, encoding: 'base64'): Base64UrlEncoded;
export function toBase64Url(string: Base64Encoded | JsonString, encoding: 'base64' | 'utf8'): Base64UrlEncoded {
  return base64url.default.encode(string, encoding) as Base64UrlEncoded;
}
