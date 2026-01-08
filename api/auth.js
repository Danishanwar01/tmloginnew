const crypto = require("crypto");
const cors = require("cors");



module.exports = (req, res) => {
    const authData = req.query;
    const hash = authData.hash;
    const BOT_TOKEN = process.env.BOT_TOKEN;

    if (!hash || !BOT_TOKEN) {
        return res.status(400).send("Missing data or token. Check Vercel Env Variables.");
    }

    // 1. Data sort + string
    const dataCheckArr = [];
    Object.keys(authData)
      .filter(key => key !== "hash")
      .sort()
      .forEach(key => dataCheckArr.push(`${key}=${authData[key]}`));

    const dataCheckString = dataCheckArr.join("\n");

    // 2. Hash verify
    const secretKey = crypto.createHash("sha256").update(BOT_TOKEN).digest();
    const hmac = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

    if (hmac === hash) {
        res.send(`<h1>Login Success! Welcome ${authData.first_name}</h1>`);
    } else {
        res.status(403).send("<h1>Verification Failed!</h1>");
    }
};