// server.js - A conceptual Node.js backend using Express and JWT
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Configure strict CORS origins in production

const JWT_SECRET = 'your_strong_fallback_secret_key';

// Mock Database of active license keys
const licenseDatabase = {
    'MECH-XXXX-YYYY-ZZZZ': { active: true, expiresAt: '2027-12-31', maxDevices: 1, activeDevices: 0 }
};

// Endpoint to validate license keys
app.post('/api/auth/verify-key', (req, res) => {
    const { licenseKey, deviceId } = req.body;

    const keyData = licenseDatabase[licenseKey];
    if (!keyData || !keyData.active || new Date() > new Date(keyData.expiresAt)) {
        return res.status(401).json({ authenticated: false, error: 'Invalid or expired license key.' });
    }

    // Generate a short-lived session token (e.g., valid for 15 minutes)
    const sessionToken = jwt.sign(
        { licenseKey, deviceId }, 
        JWT_SECRET, 
        { expiresIn: '15m' }
    );

    return res.json({ authenticated: true, token: sessionToken });
});

// Endpoint for periodic background revalidation (Heartbeat)
app.post('/api/auth/heartbeat', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ valid: false });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ valid: false, error: 'Session expired.' });

        // Double-check database status to allow instant remote revoking
        const keyData = licenseDatabase[decoded.licenseKey];
        if (!keyData || !keyData.active) {
            return res.status(403).json({ valid: false, error: 'Key revoked.' });
        }

        // Return a fresh token to extend the sliding session window
        const freshToken = jwt.sign(
            { licenseKey: decoded.licenseKey, deviceId: decoded.deviceId }, 
            JWT_SECRET, 
            { expiresIn: '15m' }
        );

        return res.json({ valid: true, token: freshToken });
    });
});

app.listen(3000, () => console.log('Authentication server running on port 3000'));