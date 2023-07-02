import { z } from 'zod';
import { JwtAlgorithmsSchema } from '../algorithms/algorithms-schema.js';

export const JwtHeaderSchema = z.object({
  typ: z.literal('JWT'),
  alg: JwtAlgorithmsSchema,
});

export type JwtHeaderSchema<EnabledAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema> = Omit<z.infer<typeof JwtHeaderSchema>, 'alg'> & {
  alg: EnabledAlgorithms;
};
