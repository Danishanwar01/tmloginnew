const crypto = require("crypto");

module.exports = async (req, res) => {
    // CORS headers set करें
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    // OPTIONS request handle करें (preflight)
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    try {
        const authData = req.query;
        const hash = authData.hash;
        const BOT_TOKEN = process.env.BOT_TOKEN;

        console.log('Received auth data:', authData);
        console.log('Bot token exists:', !!BOT_TOKEN);

        if (!hash || !BOT_TOKEN) {
            console.error('Missing hash or bot token');
            return res.status(400).json({ 
                error: 'Missing authentication data or bot token' 
            });
        }

        // 1. Data को sort और stringify करें
        const dataCheckArr = [];
        Object.keys(authData)
            .filter(key => key !== 'hash')
            .sort()
            .forEach(key => {
                dataCheckArr.push(`${key}=${authData[key]}`);
            });

        const dataCheckString = dataCheckArr.join('\n');
        console.log('Data check string:', dataCheckString);

        // 2. Secret key generate करें
        const secretKey = crypto
            .createHash('sha256')
            .update(BOT_TOKEN)
            .digest();

        // 3. HMAC verify करें
        const hmac = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');

        console.log('Computed HMAC:', hmac);
        console.log('Received hash:', hash);

        if (hmac === hash) {
            // Success response
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Successful</title>
                    <meta charset="UTF-8">
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            text-align: center; 
                            padding: 50px; 
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                        }
                        .container {
                            background: rgba(255, 255, 255, 0.1);
                            padding: 40px;
                            border-radius: 15px;
                            backdrop-filter: blur(10px);
                            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>✅ Login Successful!</h1>
                        <p>Welcome, <strong>${authData.first_name || 'User'}</strong></p>
                        <p>Telegram ID: ${authData.id}</p>
                        <p>You will be redirected in 3 seconds...</p>
                    </div>
                    <script>
                        setTimeout(() => {
                            window.location.href = "/";
                        }, 3000);
                    </script>
                </body>
                </html>
            `);
        } else {
            res.status(403).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Verification Failed</title>
                    <meta charset="UTF-8">
                </head>
                <body>
                    <h1>❌ Verification Failed!</h1>
                    <p>Authentication data is tampered or invalid.</p>
                    <p><a href="/">Go back to home</a></p>
                </body>
                </html>
            `);
        }
    } catch (error) {
        console.error('Error in auth endpoint:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
};