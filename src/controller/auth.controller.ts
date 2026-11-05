import { Request, Response } from "express";
import { UserRegisterSchema } from "../validation/register.validation";
import { toFieldsErrors } from "../lib/utils/input.utils";
import { prisma } from "../lib/prisma";
import bcrypt from "bcryptjs";
import { UserLoginSchema } from "../validation/login.validation";
import {
  clearAuthCookies,
  createToken,
  getRefreshTokenExpiry,
  hashRefreshToken,
  setTokenCookie,
  signToken,
  verifyToken,
} from "../lib/utils/auth.utils";
import jwt from "jsonwebtoken";
import crypto from 'crypto';
//________________________________________________________________________________________
export async function registerHandler(req: Request, res: Response) {
  const validation = UserRegisterSchema.safeParse(req.body);
  if (!validation.success) {
    const fieldErrors = toFieldsErrors(validation.error);
    return res.status(400).json({
      message: "Invalid inputs",
      errors: fieldErrors,
    });
  }
  // Use validated data
  const { name, email, password } = validation.data;
  try {
    // 2. Check if the user already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser)
      return res.status(409).json({ message: "Email already registered" });
    // 3. Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    // 4. Create user
    await prisma.user.create({
      data: {
        name,
        email,
        passwordHash: hashedPassword,
      },
    });
    // TODO: Implement email verification logic here
    // (e.g., send a verification email with a token)

    // 5. Return response
    return res.status(201).json({
      message: "Registration successful",
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
//________________________________________________________________________________________
// Used to keep response time similar when the email doesn't exist.
// Use the same cost factor (12 here) as in your register handler.
const DUMMY_HASH = bcrypt.hashSync("dummy-password", 12);
export async function loginHandler(req: Request, res: Response) {
  const validation = UserLoginSchema.safeParse(req.body);
  if (!validation.success) {
    return res.status(400).json({ message: "Invalid input" });
  }
  const { email, password } = validation.data;
  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });
    const passwordMatch = await bcrypt.compare(
      password,
      user?.passwordHash ?? DUMMY_HASH,
    );
    if (!user || !user.passwordHash || !passwordMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (
      !user.emailVerified &&
      process.env.REQUIRE_EMAIL_VERIFICATION === "true"
    ) {
      return res
        .status(403)
        .json({ message: "Please verify your email before you login" });
    }
    const payload = {
      sub: user.id,
      role: user.role,
      tokenVersion: user.tokenVersion,
    };
    // Keep access tokens short lived; persist only a hash of the refresh token.
    createToken("access", res, payload);
    const refreshToken = signToken("refresh", payload);
    await prisma.refreshToken.create({
      data: {
        tokenHash: hashRefreshToken(refreshToken),
        userId: user.id,
        expiresAt: getRefreshTokenExpiry(),
      },
    });
    setTokenCookie("refresh", res, refreshToken);
    return res.status(200).json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: `Internal server error` });
  }
}

//________________________________________________________________________________________
export async function refreshTokenHandler(req: Request, res: Response) {
  const token = req.cookies?.refresh_token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const payload = verifyToken("refresh", token);
    const tokenHash = hashRefreshToken(token);
    const storedToken = await prisma.refreshToken.findUnique({
      where: { tokenHash },
    });
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (
      !storedToken ||
      storedToken.userId !== payload.sub ||
      storedToken.revokedAt ||
      storedToken.expiresAt <= new Date() ||
      !user ||
      user.tokenVersion !== payload.tokenVersion
    ) {
      clearAuthCookies(res);
      return res.status(401).json({ message: "Unauthorized" });
    }

    const newPayload = {
      sub: user.id,
      role: user.role,
      tokenVersion: user.tokenVersion,
    };
    const newRefreshToken = signToken("refresh", newPayload);
    const now = new Date();
    // Revoke the presented token and create its replacement atomically. Only
    // one concurrent refresh can rotate a given token successfully.
    const rotated = await prisma.$transaction(async (tx) => {
      const revoked = await tx.refreshToken.updateMany({
        where: { id: storedToken.id, revokedAt: null, expiresAt: { gt: now } },
        data: { revokedAt: now },
      });
      if (revoked.count !== 1) return false;
      await tx.refreshToken.create({
        data: {
          tokenHash: hashRefreshToken(newRefreshToken),
          userId: user.id,
          expiresAt: getRefreshTokenExpiry(),
        },
      });
      return true;
    });
    if (!rotated) {
      clearAuthCookies(res);
      return res.status(401).json({ message: "Unauthorized" });
    }

    createToken("access", res, newPayload);
    setTokenCookie("refresh", res, newRefreshToken);

    return res.status(200).json({ message: "Token refreshed" });
  } catch (error) {
    // covers invalid signature and TokenExpiredError (a subclass)
    if (error instanceof jwt.JsonWebTokenError) {
      clearAuthCookies(res);
      return res.status(401).json({ message: "Unauthorized" });
    }
    console.error("Refresh token error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
//________________________________________________________________________________________
export async function logoutHandler(req: Request, res: Response) {
  const token = req.cookies?.refresh_token;
  clearAuthCookies(res);

  if (typeof token === "string" && token.length > 0) {
    try {
      await prisma.refreshToken.updateMany({
        where: { tokenHash: hashRefreshToken(token), revokedAt: null },
        data: { revokedAt: new Date() },
      });
    } catch {
      return res.status(503).json({
        message:
          "Cookies cleared, but session revocation could not be confirmed.",
      });
    }
  }

  return res.status(200).json({ message: "Logged out successfully" });
}

export async function forgetPassword(req: Request, res: Response) {
  const { email } = req.body as { email?: string };
  if(!email) res.status(400).json({ message: "Email is required" });
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if(!user) return res.status(400).json({ message: "Invalid email" });
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHahs = crypto.createHash('sha256').update(rawToken).digest('hex');
    const duration = (Number(process.env.RESET_PASSWORD_EXPIRES) ?? 5) * 60 * 1000;
    const resetPasswordExpires = new Date(Date.now() + duration);
    user.resetPasswordToken = tokenHahs;
    user.resetPasswordExpires = resetPasswordExpires;
    await prisma.user.update({ where: { id: user.id }, data: user });
    const baseUrl = process.env.NODE_ENV === "development" ? process.env.APP_PRIVATE_URL : process.env.APP_PUBLIC_URL
    const resetUrl = `${baseUrl}/auth/reset-password?token=${rawToken}`;
    // Send email to user resetPasswordToken not the hashed
    // Send the raw token to the user in the link
    // When user comes back with raw token, you hash it and compare to DB
    return res
      .status(200)
      .json({ message: "If an account exists, a reset link has been sent. Check your inbox and spam folder." });
  } catch (error) {
    console.error("Forget password error,", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}