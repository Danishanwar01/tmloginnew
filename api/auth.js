import crypto from "crypto";
import jwt from "jsonwebtoken";

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "Method not allowed" });
  }

  const user = req.body;

  // 1️⃣ Create secret from BOT TOKEN
  const secret = crypto
    .createHash("sha256")
    .update(process.env.BOT_TOKEN)
    .digest();

  // 2️⃣ Create data-check string
  const checkString = Object.keys(user)
    .filter(key => key !== "hash")
    .sort()
    .map(key => `${key}=${user[key]}`)
    .join("\n");

  // 3️⃣ Generate HMAC
  const hmac = crypto
    .createHmac("sha256", secret)
    .update(checkString)
    .digest("hex");

  // 4️⃣ Compare hash
  if (hmac !== user.hash) {
    return res.status(401).json({ message: "Invalid Telegram data" });
  }

  // 5️⃣ Create JWT
  const token = jwt.sign(
    {
      telegramId: user.id,
      username: user.username
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.status(200).json({
    message: "Telegram login successful",
    token,
    user
  });
}
