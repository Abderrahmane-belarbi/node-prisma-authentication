import { Router, Request, Response } from "express";
import { authenticate } from "../middleware/auth.middleware";
import { getUserProfile } from "../controller/user.controller";

const router = Router();

router.get('/me', authenticate, getUserProfile);
export default router;