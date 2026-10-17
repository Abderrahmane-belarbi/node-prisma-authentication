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

  },
  refresh: {
    secret: process.env.JWT_REFRESH_SECRET!,
    cookieName: 'access_token',
    duration: 30 * 24 * 60 * 60
  }
}

export function createToken(
  tokenType: 'access' | 'refresh',
  res: Response,
  payload: Payload
) {
  const config = TOKEN_CONFIG[tokenType];
  const token = jwt.sign(payload, config.secret, {
    expiresIn: config.duration
  });

  return res.cookie(config.cookieName, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: config.duration * 1000
  });
}
