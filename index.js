const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');
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
    store: MongoStore.create({
        mongoUrl: 'mongodb+srv://bhumi:bhumi123@secrets.bfursja.mongodb.net/secrets',
    }),
    cookie: {
        httpOnly: true,          
        secure: true,          
        maxAge: 1000 * 60 * 60   
    }
}));

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

app.post('/register', async function (req, res) {
    const { name, username, password } = req.body;
    const errors = [];

    // Validate Name
    if (!name || name.trim().length < 2) {
        errors.push("Name must be at least 2 characters.");
    }

    // Validate Email Format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) {
        errors.push("Please enter a valid email address.");
    }

    // Validate Password Format
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
    if (!passwordRegex.test(password)) {
        errors.push("Password must be minimum 6 characters with lowercase, uppercase, and number.");
    }

    if (errors.length > 0) {
        return res.render("register", { errors, old: { name, username } });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email: username });
        if (existingUser) {
            return res.render("register", {
                errors: ["Email already registered."],
                old: { name, username }
            });
        }

        // ✅ Hash the password
        const hashedPassword = await bcrypt.hash(password, 12);

        // ✅ Save with all fields
        const newUser = new User({
            name,
            email: username,
            password: hashedPassword
        });

        await newUser.save();
        res.redirect("/login");
    } catch (err) {
        console.error("Registration error:", err);
        res.render("register", {
            errors: ["Something went wrong, please try again."],
            old: { name, username }
        });
    }
});



app.get('/login', (req, res) => {
    res.render('login');
});


app.post("/login", async function (req, res) {
    const { username, password } = req.body;
    const errors = [];

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) {
        errors.push("Please enter a valid email address.");
    }

    // Password basic validation
    if (!password || password.length < 6) {
        errors.push("Password must be at least 6 characters.");
    }

    if (errors.length > 0) {
        return res.render("login", {
            errors,
            old: { username }
        });
    }

    try {
        const user = await User.findOne({ email: username });

        if (!user) {
            return res.render("login", {
                errors: ["Invalid email or password."],
                old: { username }
            });
        }

        // If you're using bcrypt to hash passwords:
        // const passwordMatch = await bcrypt.compare(password, user.password);

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.render("login", {
                errors: ["Invalid email or password."],
                old: { username }
            });
        }

        // Success: redirect to protected page
       const token = jwt.sign(
            { id: user._id, name: user.name, email: user.email },
            process.env.JWT_SECRET || 'jwtsecretkey',
            { expiresIn: '1h' }
        );
        res.cookie('token', token, {
            httpOnly: true,
            secure: true, // set to true in production with HTTPS
            maxAge: 60 * 60 * 1000
        });
        res.redirect("/secrets");


    } catch (err) {
        console.log(err);
        res.render("login", {
            errors: ["Something went wrong. Try again later."],
            old: { username }
        });
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
