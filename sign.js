const secret = "SHA_SECRET";

const body = JSON.stringify({
  to: "sourva55@gmail.com",
  subject: "Test Email",
  text: "Hello from Hono + Bun 🚀",
});

const encoder = new TextEncoder();

const key = await crypto.subtle.importKey(
  "raw",
  encoder.encode(secret),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign"],
);

const signatureBuffer = await crypto.subtle.sign(
  "HMAC",
  key,
  encoder.encode(body),
);

// convert to hex
const signature = Array.from(new Uint8Array(signatureBuffer))
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

console.log("Signature:", signature);
console.log("Body:", body);
