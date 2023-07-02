import { describe, expect, it } from 'vitest';
import { JwtError } from '../index.js';

describe('JwtError', () => {
  it('should exist', () => {
    expect(JwtError).toBeTruthy();
  });
});
