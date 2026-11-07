import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { createHash } from "node:crypto";
import { Role } from "../../../generated/prisma/enums";
import { sendMail } from "../../config/send-mail";
import { requireEnv } from "./input.utils"; 

type Payload = {
  sub: string;
  role: Role;
  tokenVersion: number;
};

type TokenType = "access" | "refresh";
export const accessTokenDuration = 15 * 60; // 15 minutes in seconds
export const refreshTokenDuration = 30 * 24 * 60 * 60; // 30 days in seconds
const TOKEN_CONFIG = {
  access: {
    secret: process.env.JWT_ACCESS_SECRET!,
    cookieName: "access_token",
    duration: accessTokenDuration,
    // The path attribute tells the browser on which URLs to send this cookie. A cookie is sent only if the request URL starts with its path.
    path: "/", // Every route (/users, /orders, /auth/...), because any protected route needs it
  },
  refresh: {
    secret: process.env.JWT_REFRESH_SECRET!,
    cookieName: "refresh_token",
    duration: refreshTokenDuration, // 30x24x60x60 seconds (30 days)
    path: "/auth", // Only /auth/... routes (refresh, logout)
  },
};

export const cookieBase = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const, // const at the end it tell typescript that we explicit want word "lax" and not as any string type inferred: { sameSite: "lax" }  ✅ accepted
};

export function createToken(
  tokenType: TokenType,
  res: Response,
  payload: Payload,
) {
  const token = signToken(tokenType, payload);
  return setTokenCookie(tokenType, res, token);
}

export function signToken(tokenType: TokenType, payload: Payload) {
  const config = TOKEN_CONFIG[tokenType];
  return jwt.sign(payload, config.secret, {
    algorithm: "HS256",
    expiresIn: config.duration,
  });
}

export function setTokenCookie(
  tokenType: TokenType,
  res: Response,
  token: string,
) {
  const config = TOKEN_CONFIG[tokenType];
  return res.cookie(config.cookieName, token, {
    ...cookieBase,
    maxAge: config.duration * 1000,
    path: config.path,
  });
}

export function getRefreshTokenExpiry() {
  return new Date(Date.now() + TOKEN_CONFIG.refresh.duration * 1000);
}

export function hashRefreshToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export function clearAuthCookies(res: Response) {
  // path must match the one used when the cookie was set
  res.clearCookie(TOKEN_CONFIG.access.cookieName, {
    ...cookieBase,
    path: TOKEN_CONFIG.access.path,
  });
  res.clearCookie(TOKEN_CONFIG.refresh.cookieName, {
    ...cookieBase,
    path: TOKEN_CONFIG.refresh.path,
  });
}

export function verifyToken(tokenType: TokenType, token: string) {
  const secret = TOKEN_CONFIG[tokenType].secret;
  return jwt.verify(token, secret, {
    algorithms: ["HS256"],
  }) as { sub: string; role: Role; tokenVersion: number };
}

export function extractAccessToken(req: Request): string | null {
  // Check the Authorization header first
  const header = req.headers.authorization;
  if (header) {
    const [scheme, token] = header.split(" ");
    return scheme.toLowerCase() === "bearer" && token ? token : null;
  }
  // Fallback to cookie if header is not present
  return req.cookies?.access_token ?? null; // web fallback
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export async function sendVerificationEmail(
  email: string,
  token: string
): Promise<void> {
  // Pass a securely generated token from your authentication logic.
  const safeToken = escapeHtml(token);

  await sendMail({
    to: email,
    subject: `Verify your email — ${requireEnv("APP_NAME")}`,

    // Fallback for email clients that don't display HTML.
    text: [
      `Welcome to ${requireEnv("APP_NAME")}!`,
      `Your verification code is: ${token}`,
      "If you didn't request this, ignore this email.",
    ].join("\n\n"),

    html: `
      <div style="font-family:Arial,sans-serif;padding:24px;color:#111827">
        <h2>Welcome to ${requireEnv("APP_NAME")}</h2>
        <p>Your verification code is:</p>

        <p style="font-size:28px;font-weight:bold;letter-spacing:4px">
          ${safeToken}
        </p>

        <p style="font-size:13px;color:#6b7280">
          If you didn't request this, ignore this email.
        </p>
      </div>
    `,
  });
}