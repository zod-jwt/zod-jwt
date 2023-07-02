import { z } from 'zod';
import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown whenever a token has a claim that fails validation.
 * This includes both the `publicClaims` and the `privateClaims`
 *
 * ---
 *
 * For `exp` this is thrown if the `exp` claim is not a number of if
 * the `compareTime` later than the claim value
 *
 * *Note: `compareTime` is the `baseTime` + `clockSkew`*
 *
 * *Note: this claim is set by default and must be present when validating*
 *
 * ---
 *
 * For `nbf` this is thrown if the `nbf` claim is not a number of if
 * the `compareTime` earlier than the claim value
 *
 * *Note: `compareTime` is the `baseTime` - `clockSkew`*
 *
 * *Note: this claim is set by default and must be present when validating*
 *
 * ---
 *
 * For `iat` this is thrown if the `iat` claim is not a number.
 *
 * *Note: this claim is set by default and must be present when validating*
 *
 * ---
 *
 * For `iss` this is thrown if it doesn't pass your zod validation
 *
 * For `sub` this is thrown if it doesn't pass your zod validation
 *
 * For `aud` this is thrown if it doesn't pass your zod validation
 *
 * For `jti` this is thrown if it doesn't pass your zod validation
 *
 * ---
 *
 * For any `privateClaims` this is thrown if it doesn't pass your zod validation
 *
 */
export class JwtTokenClaimError extends JwtError {
  zodError: z.ZodError<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(error: { message: string; zodError: z.ZodError<any> }) {
    super(`[${JwtTokenClaimError.name}]: ${error.message}`);
    Object.setPrototypeOf(this, JwtTokenClaimError.prototype);
    this.zodError = error.zodError;
  }
}
