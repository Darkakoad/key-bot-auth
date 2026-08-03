const { Client, GatewayIntentBits } = require('discord.js');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

// 1. Setup SQLite Database
const db = new sqlite3.Database(path.join(__dirname, 'keys.db'));
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS keys (key TEXT PRIMARY KEY, hwid TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME)");
});

// 2. Setup Express Web Server
const app = express();
const port = 3000;

app.get('/api/check-key', (req, res) => {
    let key = req.query.key;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    
    // Generate a pseudo-HWID from the IP if the C loader didn't send a real one
    // (This mimics our previous fix, making it secure and automatic)
    const hwid = req.query.hwid || crypto.createHash('md5').update(clientIp + "-spoofer").digest('hex');

    if (!key) {
        return res.status(400).json({ valid: false, error: "No key provided" });
    }
    
    key = key.trim();
    
    // Check key in database
    db.get("SELECT * FROM keys WHERE key = ?", [key], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ valid: false, error: "Database error" });
        }
        
        if (!row) {
            return res.status(200).json({ valid: false, error: "Invalid Key." });
        }
        
        // Check if key is expired
        if (row.expires_at) {
            const now = new Date();
            const expires = new Date(row.expires_at);
            if (now > expires) {
                return res.status(200).json({ valid: false, error: "Key Expired." });
            }
        }
        
        // Key exists, check HWID binding
        if (!row.hwid) {
            // First time use: bind the HWID
            db.run("UPDATE keys SET hwid = ? WHERE key = ?", [hwid, key], (updateErr) => {
                if (updateErr) {
                    return res.status(500).json({ valid: false, error: "Failed to bind HWID" });
                }
                console.log(`[AUTH] Key ${key} bound to HWID: ${hwid}`);
                return res.status(200).json({ valid: true });
            });
        } else {
            // Key is already bound, verify HWID matches
            if (row.hwid === hwid) {
                console.log(`[AUTH] Successful login for key ${key}`);
                return res.status(200).json({ valid: true });
            } else {
                console.log(`[AUTH] HWID Mismatch for key ${key}`);
                return res.status(200).json({ valid: false, error: "HWID Mismatch." });
            }
        }
    });
});

// Helper for generating keys
function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Work.ink Flow Routes
const WORK_INK_URL = "https://work.ink/2O4t/key"; // His real work.ink link

app.get('/getkey', (req, res) => {
    // Redirect the user to the Work.ink link
    res.redirect(WORK_INK_URL);
});

app.get('/success', (req, res) => {
    // Generate a 24-hour key
    const newKey = `ONYX-${generateRandomString(6)}-${generateRandomString(6)}-${generateRandomString(6)}`;
    
    // Set expiration to 24 hours from now
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    const expiresStr = expiresAt.toISOString();

    db.run("INSERT INTO keys (key, hwid, expires_at) VALUES (?, NULL, ?)", [newKey, expiresStr], (err) => {
        if (err) {
            console.error(err);
            return res.send("<h1>Database error generating key.</h1>");
        }
        
        // Display the key to the user
        res.send(`
            <body style="background-color: #0f0f13; color: white; font-family: monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh;">
                <h2 style="color: #4a90e2;">Your 24-Hour Key</h2>
                <div style="background: #1c1c24; padding: 20px; border-radius: 8px; font-size: 24px; border: 1px solid #333;">
                    ${newKey}
                </div>
                <p style="color: #888; margin-top: 20px;">Copy this key and paste it into the loader.</p>
                <p style="color: #ff4a4a;">Note: This key will expire in exactly 24 hours.</p>
            </body>
        `);
        console.log(`[WEB] Generated 24-hour key via ad link: ${newKey}`);
    });
});

app.listen(port, () => {
    console.log(`[WEB] Authentication API listening at http://localhost:${port}`);
});

// 3. Setup Discord Bot
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ] 
});

const PREFIX = '!';

client.on('ready', () => {
    console.log(`[DISCORD] Logged in as ${client.user.tag}!`);
    console.log(`[DISCORD] Use ${PREFIX}genkey to generate a new key.`);
});

client.on('messageCreate', (message) => {
    if (message.author.bot) return;
    
    if (message.content.startsWith(`${PREFIX}genkey`)) {
        // Basic permission check - you might want to restrict this to your user ID
        // if (message.author.id !== 'YOUR_DISCORD_ID') return;
        
        // Generate a key like ONYX-XXXX-XXXX-XXXX
        const newKey = `ONYX-${generateRandomString(6)}-${generateRandomString(6)}-${generateRandomString(6)}`;
        
        // Command generated keys can be lifetime or 24h depending on what you want. We'll make them lifetime by default.
        db.run("INSERT INTO keys (key, hwid, expires_at) VALUES (?, NULL, NULL)", [newKey], (err) => {
            if (err) {
                console.error(err);
                return message.reply("❌ Database error while generating key.");
            }
            
            message.reply(`✅ Successfully generated new key:\n\`\`\`${newKey}\`\`\``);
            console.log(`[DISCORD] Generated new key: ${newKey}`);
        });
    }
});

// Login using the provided token from environment variables
client.login(process.env.DISCORD_TOKEN);
