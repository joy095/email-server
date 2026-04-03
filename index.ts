import { Hono } from "hono";
import { cors } from "hono/cors";
import nodemailer from "nodemailer";
import { logger } from "hono/logger";
import { secureHeaders } from "hono/secure-headers";
import { env } from "hono/adapter";
import type { Context, Next } from "hono";

const PORT = process.env.PORT || 5000;

type Variables = {
  parsedBody: EmailRequest;
};

// 1. Define the shape of your expected Request Body
interface EmailRequest {
  to: string;
  subject: string;
  text?: string;
  html?: string;
  from?: string;
}

// 2. Define Environment Variables for Type Safety
type Bindings = {
  SMTP_USER: string;
  SMTP_PASS: string;
  FRONTEND_URL: string;
  MAIL_HMAC_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use(logger());
app.use(secureHeaders());

// CORS configuration
app.use(
  "*",
  cors({
    origin: (origin, c) => {
      const { FRONTEND_URL } = env(c);
      const allowed = FRONTEND_URL;
      return origin === allowed ? origin : allowed;
    },
    allowHeaders: ["Content-Type", "x-signature"],
    allowMethods: ["POST", "OPTIONS"],
  }),
);

/**
 * HMAC Verification Middleware
 */
const verifyHMAC = async (
  c: Context<{ Bindings: Bindings; Variables: Variables }>,
  next: Next,
) => {
  const signature = c.req.header("x-signature");
  const { MAIL_HMAC_SECRET } = env(c);

  const secret = MAIL_HMAC_SECRET;

  const rawBody = await c.req.text();

  // 🔍 ADD THESE LOGS HERE
  // console.log("Signature (from header):", signature);
  // console.log("Secret (env):", secret);
  // console.log("Raw Body (received):", rawBody);

  if (!signature || !secret) {
    return c.json({ error: "Unauthorized: Missing credentials" }, 401);
  }

  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );

    const sigBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte: string) => parseInt(byte, 16)) ||
        [],
    );

    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBuffer,
      encoder.encode(rawBody),
    );

    // console.log("HMAC valid:", isValid); // 👈 also useful

    if (!isValid) {
      return c.json({ error: "Invalid Signature" }, 403);
    }

    c.set("parsedBody", JSON.parse(rawBody));

    await next();
  } catch (err) {
    console.error("Verification error:", err);
    return c.json({ error: "Verification failed" }, 400);
  }
};

// Default Route
app.get("/", (c) => c.text("Email Service Online"));

// Email Route
app.post("/send-email", verifyHMAC, async (c) => {
  // Retrieve the body from the context (set in middleware)
  const body = c.get("parsedBody");
  const { to, subject, text, html, from } = body;

  const { SMTP_USER, SMTP_PASS } = env(c);

  if (!to || !subject || (!text && !html)) {
    return c.json({ error: "Missing required fields" }, 400);
  }

  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });

  try {
    await transporter.sendMail({
      from: from || SMTP_USER,
      to,
      subject,
      text,
      html,
    });

    return c.json({ message: "Email sent successfully" });
  } catch (error) {
    console.error("Nodemailer Error:", error);
    return c.json({ error: "Failed to send email" }, 500);
  }
});

export default {
  port: PORT,
  fetch: app.fetch,
};
