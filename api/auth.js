const crypto = require("crypto");
const cors = require("cors");

const corsHandler = cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

module.exports = (req, res) => {
  // 🔥 CORS invoke
  corsHandler(req, res, () => {

    // Preflight request handle
    if (req.method === "OPTIONS") {
      return res.status(200).end();
    }

    const authData = req.query;
    const hash = authData.hash;
    const BOT_TOKEN = process.env.BOT_TOKEN;

    if (!hash || !BOT_TOKEN) {
      return res.status(400).send("Missing data or token");
    }

    // 1. Data sort + string
    const dataCheckArr = [];
    Object.keys(authData)
      .filter(key => key !== "hash")
      .sort()
      .forEach(key => dataCheckArr.push(`${key}=${authData[key]}`));

    const dataCheckString = dataCheckArr.join("\n");

    // 2. Hash verify
    const secretKey = crypto
      .createHash("sha256")
      .update(BOT_TOKEN)
      .digest();

    const hmac = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    if (hmac === hash) {
      res.send(`
        <h1>Login Successful!</h1>
        <p>Hello, ${authData.first_name} (ID: ${authData.id})</p>
        <script>
          setTimeout(() => {
            window.location.href = "/";
          }, 3000);
        </script>
      `);
    } else {
      res.status(403).send("<h1>Verification Failed!</h1><p>Data is tampered.</p>");
    }
  });
};
