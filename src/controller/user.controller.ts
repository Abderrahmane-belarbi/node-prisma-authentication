import { Request, Response } from "express";
import { prisma } from "../lib/prisma";

export async function getUserProfile(req: Request, res: Response) {
  const email = await req.body.email;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    return res.status(200).json({ message: "User profile", data: user });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "err" })
  }
}