const express = require('express');
const app = express();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

require('dotenv').config();

console.log(process.env.DATABASE_URL);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json());

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const passwordHash = await hashPassword(password);

    try {
        await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.log(error)
        res.status(500).json({ error: 'User registration failed' });
    }
});

const jwt = require('jsonwebtoken');

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && await bcrypt.compare(password, user.password_hash)) {
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

const passport = require('passport');
const { Strategy, ExtractJwt } = require('passport-jwt');

passport.use(new Strategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}, async (jwtPayload, done) => {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [jwtPayload.id]);
    const user = result.rows[0];
    return user ? done(null, user) : done(null, false);
}));

app.use(passport.initialize());

app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: `Welcome ${req.user.email}` });
});

// Define the port for the server to listen on
const PORT = process.env.PORT || 4000;

// Start the Express server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

const saltRounds = 10;

// Hashing function
async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}
