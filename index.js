const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const session = require('express-session');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false }
}));

mongoose.connect('mongodb+srv://bhumi:bhumi123@secrets.bfursja.mongodb.net/secrets?retryWrites=true&w=majority');

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model('User', userSchema);

// Validate password format
function isValidPassword(password) {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,8}$/.test(password);
}

// Middleware to check JWT and session
function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, process.env.JWT_SECRET || 'jwtsecretkey', (err, decoded) => {
        if (err) return res.redirect('/login');
        req.user = decoded;
        next();
    });
}

// ROUTES

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { name, username: email, password } = req.body;

    if (!validator.isEmail(email)) {
        return res.send("Invalid email format.");
    }

    if (!isValidPassword(password)) {
        return res.send("Password must be 6–8 characters, include uppercase, lowercase and a number.");
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    try {
        await User.create({ name, email, password: hashedPassword });
        res.redirect('/login');
    } catch (err) {
        console.log(err);
        res.status(500).send("Registration failed.");
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username: email, password } = req.body;

    if (!validator.isEmail(email)) {
        return res.send("Invalid email format.");
    }

    try {
        const user = await User.findOne({ email });
        if (!user) return res.send("User not found.");

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.send("Invalid credentials.");

        const token = jwt.sign({ id: user._id, name: user.name }, process.env.JWT_SECRET || 'jwtsecretkey', {
            expiresIn: '1h'
        });

        res.cookie('token', token, { httpOnly: true });
        res.redirect('/secrets');
    } catch (err) {
        res.status(500).send("Login failed.");
    }
});

app.get('/secrets', authenticate, (req, res) => {
    res.render('secrets', { user: req.user });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
