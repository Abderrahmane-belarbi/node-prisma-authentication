import { Response } from "express";
import jwt from 'jsonwebtoken';
import { Role } from "../../../generated/prisma/enums";

type Payload = {
  sub: string;
  role: Role;
  tokenVersion: number
}

const TOKEN_CONFIG = {
  access: {
    secret: process.env.JWT_ACCESS_SECRET!,
    cookieName: 'access_token',
    duration: 15 * 60,
    // The path attribute tells the browser on which URLs to send this cookie. A cookie is sent only if the request URL starts with its path.
    path: "/" // Every route (/users, /orders, /auth/...), because any protected route needs it

  },
  refresh: {
    secret: process.env.JWT_REFRESH_SECRET!,
    cookieName: 'refresh_token',
    duration: 30 * 24 * 60 * 60,
    path: "/auth" // Only /auth/... routes (refresh, logout)
  }
}

const cookieBase = { 
  httpOnly: true, 
  secure: process.env.NODE_ENV === "production", 
  sameSite: "lax" as const // const at the end it tell typescript that we explicit want word "lax" and not as any string type inferred: { sameSite: "lax" }  ✅ accepted
}; 

export function createToken(
  tokenType: 'access' | 'refresh',
  res: Response,
  payload: Payload
) {
  const config = TOKEN_CONFIG[tokenType];
  const token = jwt.sign(payload, config.secret, {
    algorithm: "HS256",
    expiresIn: config.duration
  });

  return res.cookie(config.cookieName, token, {
    ...cookieBase,
    maxAge: config.duration * 1000,
    path: config.path 
  });
}

export function clearAuthCookies(res: Response) {
  // path must match the one used when the cookie was set
  res.clearCookie(TOKEN_CONFIG.access.cookieName, { ...cookieBase, path: TOKEN_CONFIG.access.path });
  res.clearCookie(TOKEN_CONFIG.refresh.cookieName, { ...cookieBase, path: TOKEN_CONFIG.refresh.path });
}