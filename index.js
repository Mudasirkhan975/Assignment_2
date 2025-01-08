const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const User = require('./model/userModel');

const PORT = 7000;

// App Initialization
const app = express();
app.use(bodyParser.json());
app.use(cors());

// MongoDB Connection
mongoose.connect('mongodb+srv://mudasir9751:CizFjcu13dkKZbjH@user.csnd5.mongodb.net/?retryWrites=true&w=majority&appName=user')
    .then(() => console.log('MongoDB Connected'))
    .catch((error) => console.log("The error is: " + error));

// Token Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send('Token is required');
    jwt.verify(token, 'secretKey', (err, decoded) => {
        if (err) return res.status(401).send('Invalid Token');
        req.user = decoded;
        next();
    });
};

// Signup Route
app.post('/api/signup', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ message: "Email already exists" });
        }
        res.status(500).json({ error: err.message });
    }
});

// Signin Route
app.post('/api/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }
        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }
        const token = jwt.sign({ userId: existingUser._id }, 'secretKey', { expiresIn: '1h' });
        res.status(200).json({ result: existingUser, token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Protected Route
app.get('/api/protected', verifyToken, async (req, res) => {
    res.status(200).json({ message: 'You have accessed a protected route', user: req.user });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});