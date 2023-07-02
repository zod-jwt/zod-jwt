import type { z } from 'zod';
import { JwtHeaderSchema } from '../header/header-schema.js';

export type IJSON = Record<string, unknown>;

export type JwtDecodedParts = {
  /**
   * Base64
   */
  header: string;
  /**
   * Base64
   */
  payload: string;
  /**
   * Base64
   */
  signature: string;
  /**
   * JSON
   */
  parsedHeader: JwtHeaderSchema;
  /**
   * JSON
   */
  parsedPayload: IJSON;
};

// User defined
export type JwtIssuerClaim = z.ZodString | z.ZodOptional<z.ZodString> | z.ZodLiteral<string> | z.ZodOptional<z.ZodLiteral<string>>;
export type JwtSubjectClaim = z.ZodString | z.ZodOptional<z.ZodString> | z.ZodLiteral<string> | z.ZodOptional<z.ZodLiteral<string>>;
export type JwtAudienceClaim = z.ZodString | z.ZodOptional<z.ZodString> | z.ZodLiteral<string> | z.ZodOptional<z.ZodLiteral<string>>;
export type JwtJtiClaim = z.ZodString | z.ZodOptional<z.ZodString> | z.ZodLiteral<string> | z.ZodOptional<z.ZodLiteral<string>>;
// Fixed
export type JwtNotBeforeClaim = z.ZodNumber;
export type JwtIssuedAtClaim = z.ZodNumber;
export type JwtExpiresAtClaim = z.ZodNumber;
