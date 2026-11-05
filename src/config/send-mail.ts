import "dotenv/config";
import { google, type gmail_v1 } from "googleapis";
import MailComposer from "nodemailer/lib/mail-composer/index.js";
import { requireEnv } from "../lib/utils";

export interface SendMailOptions {
  to: string;
  subject: string;
  text?: string;
  html?: string;
}

function validateEmail(value: string): void {
  // Accept one simple email address, not a recipient list.
  if (
    typeof value !== "string" ||
    !/^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/.test(value)
  ) {
    throw new Error("Invalid email address");
  }
}

let gmailClient: gmail_v1.Gmail | undefined;

function getGmailClient(): gmail_v1.Gmail {
  if (!gmailClient) {
    const oauth2Client = new google.auth.OAuth2(
      requireEnv("GOOGLE_CLIENT_ID"),
      requireEnv("GOOGLE_CLIENT_SECRET"),
    );

    oauth2Client.setCredentials({
      refresh_token: requireEnv("REFRESH_TOKEN"),
    });

    gmailClient = google.gmail({
      version: "v1",
      auth: oauth2Client,
    });
  }

  return gmailClient;
}

export async function sendMail({
  to,
  subject,
  text,
  html,
}: SendMailOptions): Promise<gmail_v1.Schema$Message> {
  validateEmail(to);

  if (
    typeof subject !== "string" ||
    !subject.trim() ||
    /[\r\n]/.test(subject)
  ) {
    throw new Error("Invalid email subject");
  }

  if (text !== undefined && typeof text !== "string") {
    throw new Error("Email text must be a string");
  }

  if (html !== undefined && typeof html !== "string") {
    throw new Error("Email HTML must be a string");
  }

  if (!text?.trim() && !html?.trim()) {
    throw new Error("Provide email text or HTML");
  }

  const from = requireEnv("EMAIL_FROM");
  validateEmail(from);

  const mail = new MailComposer({
    from: {
      name: requireEnv("APP_NAME"),
      address: from,
    },
    to: { name: "", address: to },
    subject,
    ...(text !== undefined ? { text } : {}),
    ...(html !== undefined ? { html } : {}),
    disableFileAccess: true,
    disableUrlAccess: true,
  });

  const message = await mail.compile().build();

  const { data } = await getGmailClient().users.messages.send({
    userId: "me",
    requestBody: {
      raw: message.toString("base64url"),
    },
  });

  // Errors propagate to the caller; handle them in your route.
  return data;
}
