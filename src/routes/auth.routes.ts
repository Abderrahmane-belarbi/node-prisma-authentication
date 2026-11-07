import { Router } from "express";
import { forgetPassword, loginHandler, logoutHandler, refreshTokenHandler, registerHandler, resendVerificationEmailHandler, resetPasswordHandler, verifyEmailHandler } from "../controller/auth.controller";
import {
  loginLimiter,
  registerLimiter,
  forgotPasswordLimiter,
  resendVerificationLimiter,
  resetPasswordLimiter,
} from "../middleware/rate-limit.middleware";

const router = Router();

router.post('/register', registerLimiter, registerHandler);
router.post('/login', loginLimiter, loginHandler);
router.post('/refresh-token', refreshTokenHandler)
router.post('/logout', logoutHandler)
router.post("/verify-email", forgotPasswordLimiter, verifyEmailHandler);
router.post("/forgot-password", forgetPassword);
router.post("/reset-password", resetPasswordLimiter, resetPasswordHandler);
router.post("/resend-verification-email", resendVerificationLimiter, resendVerificationEmailHandler);

export default router;