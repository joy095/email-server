import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { timeout } from "hono/timeout";
import { rateLimiter } from "hono-rate-limiter";
import nodemailer from "nodemailer";

// ── Types ────────────────────────────────────────────────────────────────────

type EmailPayload = {
  from: string;
  to: string;
  subject: string;
  text?: string;
  html?: string;
};

// ── Environment ──────────────────────────────────────────────────────────────

const MAIL_HMAC_SECRET = process.env.MAIL_HMAC_SECRET ?? "";
const SMTP_HOST = process.env.SMTP_HOST ?? "smtp.ethereal.email";
const SMTP_PORT = Number(process.env.SMTP_PORT ?? 587);
const SMTP_USER = process.env.SMTP_USER ?? "";
const SMTP_PASS = process.env.SMTP_PASS ?? "";
const PORT = Number(process.env.PORT ?? 3000);

// Comma-separated list of trusted caller origins, e.g.:
// "https://my-worker.workers.dev,https://my-app.vercel.app"
// Leave empty to allow all origins (still requires valid HMAC).
const ALLOWED_CALLER_ORIGINS = (process.env.ALLOWED_CALLER_ORIGINS ?? "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// Rate limiting (hono-rate-limiter)
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 20);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);

if (!MAIL_HMAC_SECRET) {
  console.error("[startup] MAIL_HMAC_SECRET env var is required");
  process.exit(1);
}

// ── Nodemailer transport ─────────────────────────────────────────────────────

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
});

// ── HMAC verification ────────────────────────────────────────────────────────

const encoder = new TextEncoder();

async function verifySignature(
  body: string,
  signature: string,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(MAIL_HMAC_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(body),
    );
    const expected = Array.from(new Uint8Array(signatureBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Constant-time comparison — prevents timing attacks
    if (expected.length !== signature.length) return false;
    let mismatch = 0;
    for (let i = 0; i < expected.length; i++) {
      mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return mismatch === 0;
  } catch {
    return false;
  }
}

// ── Caller IP helper ─────────────────────────────────────────────────────────
// Cloudflare sets CF-Connecting-IP.
// Vercel / other proxies set X-Forwarded-For (first entry is the real client).
// Falls back to "unknown" for direct / local calls.

function getCallerIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

// ── Hono app ─────────────────────────────────────────────────────────────────

const app = new Hono();

// Request logging
app.use("*", logger());

// Global 10 s timeout — guards against slow clients
app.use("*", timeout(10_000));

// Rate limiting — keyed by real caller IP across CF, Vercel, and local.
// hono-rate-limiter handles the in-process store; swap `keyGenerator` for
// an Upstash store if you need cross-instance limiting.
app.use(
  "*",
  rateLimiter({
    windowMs: RATE_LIMIT_WINDOW_MS,
    limit: RATE_LIMIT_MAX,
    standardHeaders: "draft-7", // sends RateLimit-* headers per RFC draft
    keyGenerator: (c) =>
      // Cloudflare → Vercel / proxies → direct
      c.req.header("cf-connecting-ip") ??
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
      "unknown",
  }),
);

// CORS — required when callers run in a browser / edge context.
// Server-to-server calls (CF Workers, Vercel functions) don't send an Origin
// header, so those pass through unrestricted regardless of this config.
app.use(
  "*",
  cors({
    origin: (origin) => {
      if (!origin) return origin; // no Origin → server-to-server, allow
      if (ALLOWED_CALLER_ORIGINS.length === 0) return origin; // open if unconfigured
      return ALLOWED_CALLER_ORIGINS.includes(origin) ? origin : null;
    },
    allowMethods: ["POST", "GET", "OPTIONS"],
    allowHeaders: ["Content-Type", "x-signature"],
    maxAge: 86_400,
  }),
);

// ── Routes ───────────────────────────────────────────────────────────────────

app.get("/", (c) => c.json({ status: "ok", ts: new Date().toISOString() }));

app.post("/send-email", async (c) => {
  const callerIp = getCallerIp(c.req.raw);

  // 1. Read raw body — must happen before JSON parsing so bytes match what was signed
  const rawBody = await c.req.text();
  const signature = c.req.header("x-signature") ?? "";

  if (!signature) {
    return c.json({ error: "Missing x-signature header" }, 401);
  }

  // 2. Verify HMAC
  const valid = await verifySignature(rawBody, signature);
  if (!valid) {
    console.warn(`[send-email] Bad signature from ${callerIp}`);
    return c.json({ error: "Invalid signature" }, 403);
  }

  // 3. Parse & validate payload
  let payload: EmailPayload;
  try {
    payload = JSON.parse(rawBody) as EmailPayload;
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const { from, to, subject, text, html } = payload;

  if (!to || !subject) {
    return c.json({ error: "Missing required fields: to, subject" }, 400);
  }
  if (!text && !html) {
    return c.json({ error: "Provide at least one of: text, html" }, 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return c.json({ error: "Invalid 'to' email address" }, 400);
  }

  // 4. Send
  try {
    const info = await transporter.sendMail({ from, to, subject, text, html });
    console.log(
      `[send-email] OK to=${to} messageId=${info.messageId} ip=${callerIp}`,
    );
    return c.json({ success: true, messageId: info.messageId });
  } catch (err) {
    console.error(`[send-email] SMTP error ip=${callerIp}`, err);
    return c.json({ error: "Failed to send email" }, 500);
  }
});

app.notFound((c) => c.json({ error: "Not found" }, 404));

app.onError((err, c) => {
  console.error("[unhandled]", err);
  return c.json({ error: "Internal server error" }, 500);
});

// ── Export / Start ────────────────────────────────────────────────────────────

export default app;
