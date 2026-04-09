require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { authenticateToken } = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// In-memory user store (replace with a DB in production)
const users = [];
const refreshTokens = [];

// ─── REGISTER ───────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
        return res.status(400).json({ error: 'All fields are required' });

    if (password.length < 8)
        return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existingUser = users.find(u => u.email === email);
    if (existingUser)
        return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: `usr_${Date.now()}`,
        username,
        email,
        password: hashedPassword
    };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully', userId: newUser.id });
});

// ─── LOGIN ───────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user)
        return res.status(401).json({ error: 'Invalid credentials' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch)
        return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    refreshTokens.push(refreshToken);

    res.json({ accessToken, refreshToken, username: user.username });
});

// ─── REFRESH TOKEN ───────────────────────────────────────
app.post('/api/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken || !refreshTokens.includes(refreshToken))
        return res.status(403).json({ error: 'Invalid refresh token' });

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Expired refresh token' });

        const newAccessToken = jwt.sign(
            { userId: user.userId },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({ accessToken: newAccessToken });
    });
});

// ─── LOGOUT ──────────────────────────────────────────────
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    const { refreshToken } = req.body;
    const idx = refreshTokens.indexOf(refreshToken);
    if (idx > -1) refreshTokens.splice(idx, 1);
    res.json({ message: 'Logged out successfully' });
});

// ─── PROTECTED: USER PROFILE ─────────────────────────────
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({
        id: user.id,
        username: user.username,
        email: user.email
    });
});

// ─── START SERVER ────────────────────────────────────────
app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${process.env.PORT}`);
});