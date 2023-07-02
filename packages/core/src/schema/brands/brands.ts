declare const __brand: unique symbol;

export type Brand<T, BrandName extends string> = T & {
  [__brand]: BrandName;
};

export type Base64UrlEncoded = Brand<string, 'base64Url'>;
export type Base64Encoded = Brand<string, 'base64'>;
/**
 * This brand represents a string that has the format
 *
 * `[base64UrlHeader].[base64UrlPayload]`
 *
 * The encoding of this string is utf8
 */
export type HeaderPayload = Brand<string, 'headerPayload'>;

export type JsonString = Brand<string, 'jsonString'>;
