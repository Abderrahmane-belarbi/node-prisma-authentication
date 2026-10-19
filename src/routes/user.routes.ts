import { Request, Response, Router } from "express";
import { authenticate } from "../middleware/auth.middleware";
import { getUserProfile } from "../controller/user.controller";

const router = Router();

router.get('/me', authenticate, getUserProfile);
router.get('/profile', authenticate, (req: Request, res: Response) => {
  res.status(200).json({ message: "User profile route" });
});
export default router;