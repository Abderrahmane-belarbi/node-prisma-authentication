import { Request, Response } from "express";
import { prisma } from "../lib/prisma";

export async function getUserProfile(req: Request, res: Response) {
  const email = await req.body.email;
  console.log("Email from request body:", email);
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    return res.status(200).json({ message: "User profile", data: user });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(errorMessage);
    return res.status(500).json({ message: "Internal server error" });
  }
}