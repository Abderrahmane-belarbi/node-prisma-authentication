import { z } from 'zod';

export const UserLoginSchema = z.object({
  email: z.email({ error: 'Invalid email address' })
    .max(50, { error: 'Email must be at most 50 characters long' }),
  password: z.string()
    .min(6, { error: 'Password must be at least 6 characters long' })
    .max(20, { error: 'Password must be at most 20 characters long' })
});

export type UserLoginInput = z.infer<typeof UserLoginSchema>;