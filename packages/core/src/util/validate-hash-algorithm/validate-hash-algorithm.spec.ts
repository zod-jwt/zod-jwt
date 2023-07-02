import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema } from '../../schema/index.js';
import { validateHashAlgorithm } from '../index.js';

describe('validateHashAlgorithm', () => {
  it('should exist', () => {
    expect(validateHashAlgorithm).toBeTruthy();
  });

  test.each([
    { algorithm: 'PS256', mgf1HashAlgorithm: 'sha384', hashAlgorithm: 'sha256' },
    { algorithm: 'PS256', mgf1HashAlgorithm: 'sha512', hashAlgorithm: 'sha256' },

    { algorithm: 'PS384', mgf1HashAlgorithm: 'sha256', hashAlgorithm: 'sha384' },
    { algorithm: 'PS384', mgf1HashAlgorithm: 'sha512', hashAlgorithm: 'sha384' },

    { algorithm: 'PS512', mgf1HashAlgorithm: 'sha256', hashAlgorithm: 'sha512' },
    { algorithm: 'PS512', mgf1HashAlgorithm: 'sha384', hashAlgorithm: 'sha512' },
  ] satisfies { algorithm: JwtAlgorithmsPSSchema; mgf1HashAlgorithm: string; hashAlgorithm: string }[])(
    '$algorithm rejects wrong mgf1HashAlgorithm of $mgf1HashAlgorithm',
    ({ algorithm, mgf1HashAlgorithm, hashAlgorithm }) => {
      expect(() => {
        validateHashAlgorithm(algorithm, mgf1HashAlgorithm, hashAlgorithm, 'privateKey');
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each([
    // es
    { algorithm: 'PS256', mgf1HashAlgorithm: 'sha256', hashAlgorithm: 'sha384' },
    { algorithm: 'PS256', mgf1HashAlgorithm: 'sha256', hashAlgorithm: 'sha512' },

    { algorithm: 'PS384', mgf1HashAlgorithm: 'sha384', hashAlgorithm: 'sha256' },
    { algorithm: 'PS384', mgf1HashAlgorithm: 'sha384', hashAlgorithm: 'sha512' },

    { algorithm: 'PS512', mgf1HashAlgorithm: 'sha512', hashAlgorithm: 'sha256' },
    { algorithm: 'PS512', mgf1HashAlgorithm: 'sha512', hashAlgorithm: 'sha384' },
  ] satisfies { algorithm: JwtAlgorithmsPSSchema; mgf1HashAlgorithm: string; hashAlgorithm: string }[])(
    '$algorithm rejects wrong hashAlgorithm of $hashAlgorithm',
    ({ algorithm, mgf1HashAlgorithm, hashAlgorithm }) => {
      expect(() => {
        validateHashAlgorithm(algorithm, mgf1HashAlgorithm, hashAlgorithm, 'privateKey');
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each([
    { algorithm: 'PS256', mgf1HashAlgorithm: 'sha256', hashAlgorithm: 'sha256' },
    { algorithm: 'PS384', mgf1HashAlgorithm: 'sha384', hashAlgorithm: 'sha384' },
    { algorithm: 'PS512', mgf1HashAlgorithm: 'sha512', hashAlgorithm: 'sha512' },
  ] satisfies { algorithm: JwtAlgorithmsPSSchema; mgf1HashAlgorithm: string; hashAlgorithm: string }[])(
    '$algorithm accepts correct mgf1HashAlgorithm of $mgf1HashAlgorithm and correct hashAlgorithm of $hashAlgorithm',
    ({ algorithm, mgf1HashAlgorithm, hashAlgorithm }) => {
      expect(() => {
        validateHashAlgorithm(algorithm, mgf1HashAlgorithm, hashAlgorithm, 'privateKey');
      }).not.toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );
});
