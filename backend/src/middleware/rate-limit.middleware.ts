import { rateLimit } from "express-rate-limit";

function createLimiter(limit: number, message: string) {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { message },
  });
}

// Each limiter has its own request counter.
export const loginLimiter = createLimiter(
  20,
  "Too many login attempts. Please try again later.",
);

export const registerLimiter = createLimiter(
  5,
  "Too many registration attempts. Please try again later.",
);

export const forgotPasswordLimiter = createLimiter(
  5,
  "Too many password reset requests. Please try again later.",
);

export const resendVerificationLimiter = createLimiter(
  5,
  "Too many verification email requests. Please try again later.",
);

export const resetPasswordLimiter = createLimiter(
  10,
  "Too many password reset attempts. Please try again later.",
);