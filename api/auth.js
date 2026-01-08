import crypto from "crypto";
import jwt from "jsonwebtoken";

export default function handler(req, res) {

  // 🔓 CORS (safe, same-origin friendly)
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ message: "Method not allowed" });
  }

  const user = req.body;

  // ⏱️ auth_date freshness (Telegram recommended)
  const now = Math.floor(Date.now() / 1000);
  if (now - user.auth_date > 60 * 60) {
    return res.status(401).json({ message: "Auth data expired" });
  }

  // 🔐 Create secret
  const secret = crypto
    .createHash("sha256")
    .update(process.env.BOT_TOKEN)
    .digest();

  // 🧾 Build check string
  const checkString = Object.keys(user)
    .filter(k => k !== "hash")
    .sort()
    .map(k => `${k}=${user[k]}`)
    .join("\n");

  // 🔑 HMAC
  const hmac = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest("hex");

  if (hmac !== user.hash) {
    return res.status(401).json({ message: "Invalid Telegram data" });
  }

  // 🎟️ JWT
  const token = jwt.sign(
    { telegramId: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  return res.status(200).json({
    message: "Telegram login successful",
    token,
    user
  });
}
