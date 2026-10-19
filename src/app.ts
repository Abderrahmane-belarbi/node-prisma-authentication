import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
import authRouter from "./routes/auth.routes"
import userRouter from "./routes/user.routes"
import { Role } from "../generated/prisma/enums";

dotenv.config();

const app = express();

// Express middleware that parses incoming JSON request bodies.
app.use(express.json()); // to parse incoming requests with JSON payloads (req.body)
// You’re telling Express: For every incoming request, if the Content-Type is application/json, parse the body.

// to parse cookies from incoming requests (req.cookies)
app.use(cookieParser());

// auth routes
app.use('/auth', authRouter);
// user routes
app.use('/users', userRouter);

function showRoles(...roles: Role[]) {
  return roles;   // an array
}

app.get("/start", (req: Request, res: Response) => {
  const data = showRoles("ADMIN", "USER"); // use your real enum values
  return res.status(200).json({ message: "Server is running", data });
});

export default app;