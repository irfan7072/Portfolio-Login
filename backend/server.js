
const express = require("express");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const path = require("path");
const crypto = require("crypto");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;
const FRONTEND_DIR = path.join(__dirname, "..", "frontend");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "IrfanPortfolio";
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!MONGODB_URI) {
    console.error("Missing MONGODB_URI. Add it to backend/.env.");
    process.exit(1);
}

if (!SESSION_SECRET) {
    console.error("Missing SESSION_SECRET. Add it to backend/.env.");
    process.exit(1);
}

const mongoClient = new MongoClient(MONGODB_URI);

let users;

// Trust proxy when deployed behind a hosting provider.
app.set("trust proxy", 1);

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

// Session configuration
app.use(
    session({
        name: "irfan_portfolio_sid",

        secret: SESSION_SECRET,

        resave: false,
        saveUninitialized: false,

        store: MongoStore.create({
            client: mongoClient,
            dbName: DB_NAME,
            collectionName: "sessions",
            ttl: 60 * 60 * 24 * 14,
            autoRemove: "native"
        }),

        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);

// Authentication rate limiter
const attempts = new Map();

function authRateLimit(req, res, next) {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();

    const recent = (attempts.get(key) || []).filter(
        time => now - time < 15 * 60 * 1000
    );

    if (recent.length >= 20) {
        return res.status(429).json({
            message: "Too many attempts. Please try again in 15 minutes."
        });
    }

    recent.push(now);
    attempts.set(key, recent);

    next();
}

// Register
app.post("/api/auth/register", authRateLimit, async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (name.length < 2 || name.length > 60) {
            return res.status(400).json({
                message: "Name must contain 2 to 60 characters."
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                message: "Enter a valid email address."
            });
        }

        if (password.length < 8 || password.length > 72) {
            return res.status(400).json({
                message: "Password must be at least 8 characters long."
            });
        }

        const existingUser = await users.findOne({ email });

        if (existingUser) {
            return res.status(409).json({
                message: "An account with this email already exists."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const user = {
            _id: crypto.randomUUID(),
            name,
            email,
            passwordHash,
            createdAt: new Date()
        };

        try {
            await users.insertOne(user);
        } catch (error) {
            if (error.code === 11000) {
                return res.status(409).json({
                    message: "An account with this email already exists."
                });
            }

            throw error;
        }

        req.session.regenerate(err => {
            if (err) {
                console.error("Session creation error:", err);

                return res.status(500).json({
                    message: "Account created, but could not start your session. Please log in."
                });
            }

            req.session.user = {
                id: user._id,
                name: user.name,
                email: user.email
            };

            req.session.save(saveError => {
                if (saveError) {
                    console.error("Session save error:", saveError);

                    return res.status(500).json({
                        message: "Account created, but could not save your session. Please log in."
                    });
                }

                return res.status(201).json({
                    message: "Account created successfully.",
                    user: req.session.user
                });
            });
        });

    } catch (error) {
        console.error("Registration error:", error);

        return res.status(500).json({
            message: "Unable to create account right now."
        });
    }
});

// Login
app.post("/api/auth/login", authRateLimit, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const user = await users.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        req.session.regenerate(err => {
            if (err) {
                console.error("Session creation error:", err);

                return res.status(500).json({
                    message: "Could not start your session."
                });
            }

            req.session.user = {
                id: user._id,
                name: user.name,
                email: user.email
            };

            req.session.save(saveError => {
                if (saveError) {
                    console.error("Session save error:", saveError);

                    return res.status(500).json({
                        message: "Could not save your session."
                    });
                }

                return res.json({
                    message: "Login successful.",
                    user: req.session.user
                });
            });
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            message: "Unable to log in right now."
        });
    }
});

// Check current logged-in user
app.get("/api/auth/me", (req, res) => {
    res.json({
        user: req.session.user || null
    });
});

// Logout
app.post("/api/auth/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({
                message: "Could not log out."
            });
        }

        res.clearCookie("irfan_portfolio_sid", {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
        });

        return res.json({
            message: "Logged out successfully."
        });
    });
});

// Login page
app.get("/", (req, res) => {
    if (req.session.user) {
        return res.redirect("/portfolio");
    }

    return res.sendFile(path.join(FRONTEND_DIR, "login.html"));
});

// Signup page
app.get("/signup", (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, "signup.html"));
});

// Protected portfolio page
app.get("/portfolio", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/");
    }

    return res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

app.get("/index.html", (req, res) => {
    res.redirect("/portfolio");
});

// Static frontend assets
app.use(express.static(FRONTEND_DIR, {
    index: false
}));

// Start server and connect to MongoDB
async function start() {
    try {
        await mongoClient.connect();

        const db = mongoClient.db(DB_NAME);

        users = db.collection("users");

        await users.createIndex(
            { email: 1 },
            { unique: true }
        );

        app.listen(PORT, () => {
            console.log(`Portfolio is running at http://localhost:${PORT}`);
            console.log(`Connected to MongoDB database: ${DB_NAME}`);
        });

    } catch (error) {
        console.error("Could not connect to MongoDB Atlas:", error);

        process.exit(1);
    }
}

start();
