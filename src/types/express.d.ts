import { Role } from "../../generated/prisma/enums";

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; role: Role, tokenVersion: number };
    }
  }
}

export {};