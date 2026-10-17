import express from "express";
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
import authRouter from "./routes/auth/auth.routes"
dotenv.config();

const app = express();

// Express middleware that parses incoming JSON request bodies.
app.use(express.json()); // to parse incoming requests with JSON payloads (req.body)
// You’re telling Express: For every incoming request, if the Content-Type is application/json, parse the body.

// to parse cookies from incoming requests (req.cookies)
app.use(cookieParser());

// auth routes
app.use('/auth', authRouter);

export default app;