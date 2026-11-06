import { Router } from "express";
import { forgetPassword, loginHandler, logoutHandler, refreshTokenHandler, registerHandler } from "../controller/auth.controller";

const router = Router();

router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.post('/refresh-token', refreshTokenHandler)
router.post('/logout', logoutHandler)
router.post("/forgot-password", forgetPassword);

export default router;