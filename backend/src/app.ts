import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
import authRouter from "./routes/auth.routes"
import userRouter from "./routes/user.routes"
import googleConnectionRouter from "./config/connect-gmail";
import { Role } from "../generated/prisma/enums";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
}));
// Express middleware that parses incoming JSON request bodies.
app.use(express.json()); // to parse incoming requests with JSON payloads (req.body)
// You’re telling Express: For every incoming request, if the Content-Type is application/json, parse the body.

// to parse cookies from incoming requests (req.cookies)
app.use(cookieParser());

// auth routes
app.use('/auth', authRouter);
// user routes
app.use('/users', userRouter);
// This route is used to initiate the OAuth2 flow for connecting to Gmail and obtaining an access token.
app.use("/auth", googleConnectionRouter);

export default app;