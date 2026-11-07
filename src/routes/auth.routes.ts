import { Router } from "express";
import { forgetPassword, loginHandler, logoutHandler, refreshTokenHandler, registerHandler, resetPasswordHandler, verifyEmailHandler } from "../controller/auth.controller";

const router = Router();

router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.post('/refresh-token', refreshTokenHandler)
router.post('/logout', logoutHandler)
router.post("/verify-email", verifyEmailHandler);
router.post("/forgot-password", forgetPassword);
router.post("/reset-password", resetPasswordHandler);

export default router;