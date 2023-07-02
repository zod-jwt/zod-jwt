import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsESSchema } from '../../schema/index.js';
import { validateCurve } from '../index.js';

describe('validateHashAlgorithm', () => {
  it('should exist', () => {
    expect(validateCurve).toBeTruthy();
  });

  test.each([
    { algorithm: 'ES256', curve: 'secp384r1' },
    { algorithm: 'ES256', curve: 'secp521r1' },

    { algorithm: 'ES384', curve: 'prime256v1' },
    { algorithm: 'ES384', curve: 'secp521r1' },

    { algorithm: 'ES512', curve: 'prime256v1' },
    { algorithm: 'ES512', curve: 'secp384r1' },
  ] satisfies { algorithm: JwtAlgorithmsESSchema; curve: string }[])('$algorithm rejects wrong curve of $curve', ({ algorithm, curve }) => {
    expect(() => {
      validateCurve(algorithm, curve, 'privateKey');
    }).toThrow(JwtProviderInvalidKeyMaterialError);
  });

  test.each([
    { algorithm: 'ES256', curve: 'prime256v1' },
    { algorithm: 'ES384', curve: 'secp384r1' },
    { algorithm: 'ES512', curve: 'secp521r1' },
  ] satisfies { algorithm: JwtAlgorithmsESSchema; curve: string }[])('$algorithm accepts correct curve of $curve', ({ algorithm, curve }) => {
    expect(() => {
      validateCurve(algorithm, curve, 'privateKey');
    }).not.toThrow(JwtProviderInvalidKeyMaterialError);
  });
});
