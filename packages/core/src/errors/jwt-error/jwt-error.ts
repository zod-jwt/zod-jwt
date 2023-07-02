/**
 * This is the base error thrown by all errors in this library.
 *
 * This error is never directly thrown.
 */
export abstract class JwtError extends Error {
  constructor(message: string) {
    super();
    this.message = message;
    if (process.env.DEBUG) {
      console.error(this.stack);
    }
    Object.setPrototypeOf(this, JwtError.prototype);
  }
}
