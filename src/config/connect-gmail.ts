import { google } from "googleapis";
import { Request, Response, Router } from "express";
import { writeFile } from "node:fs/promises";
import { requireEnv } from "../lib/utils/input.utils";

const router = Router();

function createOAuthClient() {
  return new google.auth.OAuth2(
    requireEnv("GOOGLE_CLIENT_ID"),
    requireEnv("GOOGLE_CLIENT_SECRET"),
    process.env.NODE_ENV === "development"
      ? requireEnv("LOCAL_GOOGLE_REDIRECT_URI")
      : requireEnv("PUBLIC_GOOGLE_REDIRECT_URI"),
  );
}

// Redirect to Google.
router.get("/google", (_req: Request, res: Response): void => {
  const oauth2Client = createOAuthClient();

  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/gmail.send"],
    prompt: "consent",
  });

  res.redirect(url);
});

// Handle Google's callback.
router.get(
  "/google/callback",
  async (req: Request, res: Response): Promise<void> => {
    if (req.query.error !== undefined) {
      res.status(400).send("Google authorization was denied or failed.");
      return;
    }

    const code = req.query.code;

    // Express query parameters are not always strings.
    if (typeof code !== "string" || !code) {
      res.status(400).send("No valid code returned from Google.");
      return;
    }

    try {
      const oauth2Client = createOAuthClient();

      const { tokens } = await oauth2Client.getToken(code);

      if (!tokens.refresh_token) {
        res.status(400).send(
          "No refresh token returned. Open /google and authorize again.",
        );
        return;
      }

      // Save locally instead of logging sensitive tokens.
      // This replaces .env.gmail if it already exists.
      await writeFile(
        ".env.gmail",
        `REFRESH_TOKEN=${tokens.refresh_token}\n`,
        { encoding: "utf8", mode: 0o600 },
      );

      res.send(
        "Authorization successful! Copy REFRESH_TOKEN from .env.gmail " +
          "into your backend .env, then restart your backend.",
      );
    } catch {
      console.error("Google token exchange or file saving failed.");
      res.status(500).send("Could not obtain or save the refresh token.");
    }
  },
);

export default router;