import { Request, Response } from "express";
import { UserRegisterSchema } from "../validation/register.validation";
import { toFieldsErrors } from "../lib/utils/input.utils";
import { prisma } from "../lib/prisma";
import bcrypt from "bcryptjs";
import { UserLoginSchema } from "../validation/login.validation";
import { createToken } from "../lib/utils/auth.utils";
export async function registerHandler(req: Request, res: Response) {
  const validation = UserRegisterSchema.safeParse(req.body);

  if (!validation.success) {
    const fieldErrors = toFieldsErrors(validation.error);
    return res.status(400).json({
      message: "Invalid inputs",
      errors: fieldErrors
    });
  }

  // Use validated data
  const { name, email, password } = validation.data;

  try {
    // 2. Check if the user already exists
    const existingUser = await prisma.user.findUnique({
      where: {
        email
      }
    });
    if (existingUser) {
      return res.status(409).json({
        message: "Email already registered",
      });
    }
    // 3. Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // 4. Create user
    await prisma.user.create({
      data: {
        name,
        email,
        passwordHash: hashedPassword
      }
    });

    // TODO: Implement email verification logic here 
    // (e.g., send a verification email with a token)

    // 5. Return response
    return res.status(201).json({
      message: "Registration successful",
    });

  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

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
      where: { email }
    });
    const passwordMatch = await bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH);
    if (!user || !user.passwordHash || !passwordMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!user.emailVerified) {
      return res.status(403).json({ message: "Please verify your email before you login" });
    }
    const payload = {
      sub: user.id,
      role: user.role,
      tokenVersion: user.tokenVersion
    };

    // Generate and set the access token in the response cookie
    createToken('access', res, payload);

    return res.status(200).json({
      message: "Login successful"
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: `Internal server error` });
  }
}