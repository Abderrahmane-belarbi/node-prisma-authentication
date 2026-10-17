import express from "express";
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
import { prisma } from "../src/lib/prisma";
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


app.get('/users', async(_, res) => {
  const users = await prisma.user.findMany();
  return res.json(users);
})

app.put('/update', async(req, res) => {
  const updated = await prisma.user.update({
    where: {
      email: "user-5@gmail.com"
    },
    data: {
      name: "user-05"
    }
  });
  return res.json(updated);
});

app.delete('/delete', async(_, res) => {
  const deleted = await prisma.user.delete({
    where: {
      email: "user-5@gmail.com"
    }
  });
  return res.json(deleted);
});
export default app;