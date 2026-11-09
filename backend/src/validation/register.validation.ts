import { z } from 'zod';

import { UserLoginSchema } from './login.validation';

export const UserRegisterSchema = UserLoginSchema.extend({
  name: z.string()
    .min(4, { error: 'Name must be at least 4 characters long' })
    .max(30, { error: 'Name must be at most 30 characters long' }),
});

export type UserRegisterInput = z.infer<typeof UserRegisterSchema>;