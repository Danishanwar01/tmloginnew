const crypto = require('crypto');

module.exports = async (req, res) => {
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const authData = req.body;
    const BOT_TOKEN = process.env.BOT_TOKEN; // Vercel dashboard mein add karna

    const { hash, ...dataToCheck } = authData;

    // Telegram verification logic
    const dataCheckString = Object.keys(dataToCheck)
        .sort()
        .map(key => `${key}=${dataToCheck[key]}`)
        .join('\n');

    const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
    const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    if (hmac === hash) {
        // Validation check: Kya data 24 ghante se purana toh nahi?
        const now = Math.floor(Date.now() / 1000);
        if (now - authData.auth_date > 86400) {
            return res.status(401).json({ success: false, message: 'Data outdated' });
        }

        return res.json({ success: true, message: 'Verified!', user: authData });
    } else {
        return res.status(401).json({ success: false, message: 'Invalid Hash' });
    }
};