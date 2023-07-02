import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema, JwtAlgorithmsRSSchema } from '../../schema/index.js';
import { validateSaltLength } from '../index.js';

describe('validateSaltLength', () => {
  it('should exist', () => {
    expect(validateSaltLength).toBeTruthy();
  });

  test.each([
    { algorithm: 'PS256', salt: 31 },
    { algorithm: 'PS384', salt: 47 },
    { algorithm: 'PS512', salt: 59 },
  ] satisfies { algorithm: JwtAlgorithmsRSSchema | JwtAlgorithmsPSSchema; salt: number }[])(
    '$algorithm rejects low salt length of $salt',
    ({ algorithm, salt }) => {
      expect(() => {
        validateSaltLength(algorithm, salt, 'privateKey');
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each([
    { algorithm: 'PS256', salt: 32 },
    { algorithm: 'PS384', salt: 48 },
    { algorithm: 'PS512', salt: 64 },
  ] satisfies { algorithm: JwtAlgorithmsRSSchema | JwtAlgorithmsPSSchema; salt: number }[])(
    '$algorithm accepts valid salt length of $salt',
    ({ algorithm, salt }) => {
      expect(() => {
        validateSaltLength(algorithm, salt, 'privateKey');
      }).not.toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );
});
