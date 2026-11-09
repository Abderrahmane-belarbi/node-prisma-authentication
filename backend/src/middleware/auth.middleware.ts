import { NextFunction, Request, Response } from "express";
import { extractAccessToken, verifyToken } from "../lib/utils/auth.utils";
import { prisma } from "../lib/prisma";
import jwt from "jsonwebtoken";

export async function authenticate(req: Request, res: Response, next: NextFunction) {
  const token = extractAccessToken(req);
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const payload = verifyToken('access', token!);
    if (!payload) return res.status(401).json({ message: "Unauthorized" });
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, role: true, tokenVersion: true }
    });
    // check if user exists and tokenVersion matches
    if (!user || user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.user = user; // need to declare this in the express Request type, see src/types/express.d.ts
    next();
  } catch (error) {
    if(error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: "Token expired" });
    }
    console.error("Auth middleware error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
