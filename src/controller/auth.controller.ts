import { Request, Response } from "express";
import { UserRegisterSchema } from "../validation/register.validation";
import { requireEnv, toFieldsErrors } from "../lib/utils/input.utils";
import { prisma } from "../lib/prisma";
import bcrypt from "bcryptjs";
import { UserLoginSchema } from "../validation/login.validation";
import {
  accessTokenDuration,
  clearAuthCookies,
  cookieBase,
  createToken,
  getRefreshTokenExpiry,
  hashRefreshToken,
  setTokenCookie,
  signToken,
  verifyToken,
} from "../lib/utils/auth.utils";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { sendMail } from "../config/send-mail";
import {
  resetPasswordTemplate,
  verificationEmailTemplate,
} from "../lib/utils/templates";
import { isValidTokenFormat } from "../lib/utils";
import { OAuth2Client } from "google-auth-library";

const appName = requireEnv("APP_NAME") || "Your App";
const baseUrl =
  process.env.NODE_ENV === "development"
    ? requireEnv("APP_PRIVATE_URL")
    : requireEnv("APP_PUBLIC_URL");
const verificationExpiresInMinutes =
  Number(process.env.EMAIL_VERIFICATION_EXPIRES) || 10;
const emailVerificationCooldown =
  Number(process.env.EMAIL_VERIFICATION_COOLDOWN) || 60;
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
    const verificationUrl = new URL("/auth/verify-email", baseUrl);
    const rawToken = crypto.randomBytes(32).toString("hex");
    verificationUrl.searchParams.set("token", rawToken);
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");
    const user = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash: hashedPassword,
        emailVerificationToken: tokenHash,
        emailVerificationExpires: new Date(
          Date.now() + verificationExpiresInMinutes * 60 * 1000,
        ),
      },
    });
    // send a verification email with a token
    try {
      await sendMail({
        to: user.email,
        subject: `Verify your email for ${appName}`,
        text: [
          `Thanks for signing up for ${appName}!`,
          "",
          "Confirm your email address using this link:",
          verificationUrl.toString(),
          "",
          `This link expires in ${verificationExpiresInMinutes} minutes.`,
          "",
          "If you did not create an account, you can ignore this email.",
        ].join("\n"),
        html: verificationEmailTemplate(
          appName,
          verificationUrl,
          verificationExpiresInMinutes,
        ),
      });
    } catch (error) {
      console.error("Failed to send verification email:", error);
      await prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerificationToken: null,
          emailVerificationExpires: null,
        },
      });
    }
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

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.body?.token;

  if (!isValidTokenFormat(token))
    return res.status(400).json({ message: "Invalid verification token." });

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await prisma.user.findUnique({
      where: {
        emailVerificationToken: tokenHash,
      },
      select: {
        id: true,
        emailVerified: true,
        emailVerificationExpires: true,
      },
    });
    if (!user)
      return res
        .status(400)
        .json({ message: "Invalid or already-used verification link." });

    if (user.emailVerified)
      return res.status(200).json({
        message: "Your email is already verified. You can log in.",
      });

    if (
      !user.emailVerificationExpires ||
      user.emailVerificationExpires.getTime() <= Date.now()
    )
      return res.status(400).json({
        message: "Verification link expired. Request a new email.",
      });

    const result = await prisma.user.updateMany({
      where: {
        emailVerificationToken: tokenHash,
        emailVerificationExpires: { gt: new Date() },
        emailVerified: null,
      },
      data: {
        emailVerified: new Date(Date.now()),
        emailVerificationToken: null,
        emailVerificationExpires: null,
      },
    });

    if (result.count !== 1)
      return res.status(400).json({
        message: "Invalid, expired, or already-used verification link.",
      });

    return res.status(200).json({
      message: "Email verified successfully. You can now log in.",
    });
  } catch (error) {
    console.error("Email verification failed.", error);
    return res.status(500).json({
      message: "Could not verify your email. Please try again.",
    });
  }
}

export async function forgetPassword(req: Request, res: Response) {
  const expiresInMinutes = Number(process.env.RESET_PASSWORD_EXPIRES) || 10;
  const { email } = req.body as { email?: string };
  if (!email) return res.status(400).json({ message: "Email is required" });
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ message: "Invalid email" });
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");
    const duration = expiresInMinutes * 60 * 1000;
    const resetPasswordExpires = new Date(Date.now() + duration);
    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = resetPasswordExpires;
    await prisma.user.update({ where: { id: user.id }, data: user });
    const resetUrl = new URL(`/auth/reset-password?token=${rawToken}`, baseUrl);
    // Send email to user resetPasswordToken not the hashed
    // Send the raw token to the user in the link
    // When user comes back with raw token, you hash it and compare to DB
    try {
      await sendMail({
        to: email!,
        subject: `Reset your ${appName} password`,

        text: [
          "to reset your password.",
          "",
          `Reset your password: ${resetUrl.toString()}`,
          "",
          `This link expires in ${expiresInMinutes} minutes.`,
          "",
          "If you did not request this, you can ignore this email.",
          "Your password has not been changed.",
        ].join("\n"),

        html: resetPasswordTemplate(appName, resetUrl, expiresInMinutes),
      });
    } catch {
      console.error("Failed to send reset password email");
      await prisma.user.updateMany({
        where: {
          id: user.id,
          resetPasswordToken: tokenHash,
        },
        data: {
          resetPasswordToken: null,
          resetPasswordExpires: null,
        },
      });
    }
    return res.status(200).json({
      message:
        "If an account exists, a reset link has been sent. Check your inbox and spam folder.",
    });
  } catch (error) {
    console.error("Forget password error,", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, newPassword } = req.body as {
    token?: string;
    newPassword?: string;
  };
  if (!token || !newPassword)
    return res
      .status(400)
      .json({ message: "Token and new password are required" });
  if (!isValidTokenFormat(token)) {
    return res.status(400).json({ message: "Invalid token format" });
  }
  const passwordValidation =
    UserRegisterSchema.shape.password.safeParse(newPassword);
  if (!passwordValidation.success) {
    return res.status(400).json({ message: "Invalid password format" });
  }
  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const user = await prisma.user.findUnique({
      where: {
        resetPasswordToken: tokenHash,
        resetPasswordExpires: { gt: new Date() },
      },
      select: {
        id: true,
        resetPasswordExpires: true,
      },
    });
    if (
      !user ||
      !user.resetPasswordExpires ||
      user.resetPasswordExpires.getTime() <= Date.now()
    ) {
      return res.status(400).json({
        message: "Invalid or expired reset link.",
      });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    const changed = await prisma.$transaction(async (tx) => {
      // Recheck token and expiry at the moment we change the password.
      const result = await tx.user.updateMany({
        where: {
          id: user.id,
          resetPasswordToken: tokenHash,
          resetPasswordExpires: { gt: new Date() },
        },
        data: {
          passwordHash: hashedPassword,
          resetPasswordToken: null,
          resetPasswordExpires: null,
          tokenVersion: { increment: 1 },
        },
      });
      if (result.count !== 1) {
        return false;
      }
      // Revoke the user's existing application refresh tokens.
      await tx.refreshToken.updateMany({
        where: {
          userId: user.id,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
      return true;
    });

    if (!changed) {
      return res.status(400).json({
        message: "Invalid, expired, or already-used reset link.",
      });
    }
    clearAuthCookies(res);
    res.status(200).json({
      message: "Password reset successful. Please log in again.",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function resendVerificationEmailHandler(
  req: Request,
  res: Response,
) {
  // Reuse the same email validation used during registration.
  const emailValidation = UserRegisterSchema.shape.email.safeParse(
    req.body?.email,
  );
  if (!emailValidation.success) {
    return res.status(400).json({
      message: "Please provide a valid email address.",
    });
  }
  const email = emailValidation.data;
  // Same response for unknown, verified, and cooldown-limited accounts.
  const response = {
    message:
      "If your account needs verification, a verification email will be sent. " +
      "Please wait at least 60 seconds before requesting another.",
  };
  try {
    if (!baseUrl) {
      throw new Error("Application URL is not configured.");
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const verificationUrl = new URL("/auth/verify-email", baseUrl);
    verificationUrl.searchParams.set("token", rawToken);

    const now = new Date();
    const nextAllowedAt = new Date(
      now.getTime() + emailVerificationCooldown * 1000,
    ); // 60 seconds cooldown

    // Check eligibility and save the new token in one database operation.
    // Concurrent requests cannot both pass the cooldown.
    const result = await prisma.user.updateMany({
      where: {
        email,
        emailVerified: null,
        OR: [
          { emailVerificationResendAvailableAt: null },
          {
            emailVerificationResendAvailableAt: {
              gte: nextAllowedAt,
            },
          },
        ],
      },
      data: {
        emailVerificationToken: tokenHash,
        emailVerificationExpires: new Date(
          now.getTime() + verificationExpiresInMinutes * 60_000,
        ),
        emailVerificationResendAvailableAt: now,
      },
    });
    if (result.count !== 1) {
      return res.status(200).json(response);
    }
    try {
      await sendMail({
        to: email,
        subject: `Verify your email for ${appName}`,
        text: [
          `Thanks for signing up for ${appName}!`,
          "",
          "Confirm your email address using this link:",
          verificationUrl.toString(),
          "",
          `This link expires in ${verificationExpiresInMinutes} minutes.`,
          "",
          "If you did not create an account, you can ignore this email.",
        ].join("\n"),
        html: verificationEmailTemplate(
          appName,
          verificationUrl,
          verificationExpiresInMinutes,
        ),
      });
    } catch {
      // Avoid logging mail errors that might contain credentials.
      console.error("Failed to send verification email.");
      // Remove only this request's token, not a newer replacement.
      // Keep the cooldown timestamp to prevent repeated failed sends.
      await prisma.user.updateMany({
        where: {
          email,
          emailVerified: null,
          emailVerificationToken: tokenHash,
        },
        data: {
          emailVerificationToken: null,
          emailVerificationExpires: null,
        },
      });
    }
    return res.status(200).json(response);
  } catch {
    console.error("Resend verification request failed.");
    return res.status(500).json({
      message: "Unable to process your request. Please try again later.",
    });
  }
}

export function getGoogleClient() {
  const clientId = requireEnv("GOOGLE_CLIENT_ID");
  const clientSecret = requireEnv("GOOGLE_CLIENT_SECRET");
  const redirectUri =
    process.env.NODE_ENV === "development"
      ? requireEnv("LOCAL_GOOGLE_REDIRECT_URI")
      : requireEnv("PUBLIC_GOOGLE_REDIRECT_URI");
  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error("Google OAuth configuration is missing.");
  }
  return new OAuth2Client({ clientId, clientSecret, redirectUri });
}

function clearGoogleOAuthStateCookie(_req: Request, res: Response) {
  res.clearCookie("google_oauth_state", {
    httpOnly: true,
    secure: process.env.MODE !== "development",
    sameSite: "lax",
  });
}

function setGoogleOAuthStateCookie(res: Response, state: string) {
  res.cookie("google_oauth_state", state, {
    ...cookieBase,
    maxAge: accessTokenDuration * 1000, // 15 minutes in milliseconds
  });
}

export async function googleLoginHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();
    const state = crypto.randomBytes(32).toString("hex");
    setGoogleOAuthStateCookie(res, state);
    const url = client.generateAuthUrl({
      access_type: "offline",
      scope: ["openid", "profile", "email"],
      prompt: "consent",
      state, // for CSRF protection
    });
    return res.redirect(url);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : error;
    console.error("Google login initiation failed:", errorMessage);
    return res.status(500).json({ error: "Failed to initiate Google login." });
  }
}

export async function googleCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string | undefined;
  const state = req.query.state;
  const stateFromCookie = req.cookies?.google_oauth_state;
  if (!code) return res.status(400).json({ error: "Code not found" });
  if (!state || !stateFromCookie || state !== stateFromCookie) {
    clearGoogleOAuthStateCookie(req, res);
    return res.status(400).json({ error: "Invalid OAuth state" });
  }
  try {
    clearGoogleOAuthStateCookie(req, res);
    const client = getGoogleClient();
    const { tokens } = await client.getToken(code);
    if (!tokens?.id_token)
      return res.status(400).json({ error: "Google ID token not found" });
    // verify token and read the user info from it
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload) {
      return res.status(400).json({ error: "Invalid Google token payload" });
    }
    const email = payload?.email;
    const emailVerified = payload?.email_verified;
    if (!email || !emailVerified)
      return res.status(400).json({ error: "Email not verified" });
    let user = await prisma.user.findUnique({
      where: { email },
    });
    if (!user) {
      user = await prisma.user.create({
        data: {
          name: payload?.name || "User",
          email,
          passwordHash: null,
          //picture: payload?.picture,
          emailVerified: new Date(),
        },
      });
    } else {
      if (!user.emailVerified) {
        await prisma.user.update({
          where: { id: user.id },
          data: {
            emailVerified: new Date(),
            emailVerificationToken: null,
            emailVerificationExpires: null,
          },
        });
      }
    }
    createToken("access", res, {
      sub: user.id,
      role: user.role,
      tokenVersion: user.tokenVersion,
    });
    const redirectUrl = `${baseUrl}/${process.env.REDIRECT_AFTER_LOGIN_URL || ""}`;
    return res.redirect(redirectUrl);
  } catch (error) {
    console.log("Login with google error:", error);
    return res.status(500).json({ message: `Internal server error` });
  }
}
