const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const jwt = require('jsonwebtoken');

app.use(express.json());

const users = new Map();
const highScores = [];

const JWT_SECRET = 'your-secret-key';

const validateLoginFields = (userHandle, password) => {
    if (!userHandle || !password) return false;
    if (typeof userHandle !== 'string' || typeof password !== 'string') return false;
    if (userHandle === '' || password === '') return false;
    if (userHandle.length < 6 || password.length < 6) return false;
    return true;
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

app.post('/signup', (req, res) => {
    const { userHandle, password } = req.body || {};

    if (!userHandle || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    if (userHandle.length < 6 || password.length < 6) {
        return res.status(400).json({ error: 'Fields must be at least 6 characters' });
    }

    users.set(userHandle, password);
    return res.status(201).send();
});

app.post('/login', (req, res) => {
    const { userHandle, password } = req.body || {};

    if (!validateLoginFields(userHandle, password)) {
        return res.status(400).json({ error: 'Invalid or missing credentials' });
    }

    const allowedFields = ['userHandle', 'password'];
    const receivedFields = Object.keys(req.body);
    if (receivedFields.some(field => !allowedFields.includes(field))) {
        return res.status(400).json({ error: 'Additional fields not allowed' });
    }

    if (!users.has(userHandle) || users.get(userHandle) !== password) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userHandle }, JWT_SECRET);
    res.status(200).json({ jsonWebToken: token });
});

app.post('/high-scores', authenticateToken, (req, res) => {
    const { level, score, timestamp, userHandle } = req.body;

    if (!userHandle || !level || typeof score !== 'number' || !timestamp) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    highScores.push({
        level,
        userHandle,
        score,
        timestamp
    });

    res.status(201).send();
});

app.get('/high-scores', (req, res) => {
    const { level, page = 1 } = req.query;

    if (!level) {
        return res.status(400).json({ error: 'Level parameter is required' });
    }

    let filteredScores = highScores
        .filter(score => score.level === level)
        .sort((a, b) => b.score - a.score);

    const pageSize = 20;
    const startIdx = (page - 1) * pageSize;
    res.status(200).json(filteredScores.slice(startIdx, startIdx + pageSize));
});

let serverInstance = null;

module.exports = {
    start: function () {
        if (!serverInstance) {
            serverInstance = app.listen(port, () => {
                console.log(`Example app listening at http://localhost:${port}`);
            });
        }
        return serverInstance;
    },
    close: function () {
        if (serverInstance) {
            serverInstance.close();
            serverInstance = null;
        }
    }
};
