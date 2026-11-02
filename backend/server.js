const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_DIR = path.join(__dirname, "..", "frontend");
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: "irfan_portfolio_sid",
  secret: process.env.SESSION_SECRET || "local-development-secret-change-before-deploying",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// Small in-memory rate limiter for authentication endpoints.
const attempts = new Map();
function authRateLimit(req, res, next) {
  const key = `${req.ip}:${req.path}`;
  const now = Date.now();
  const recent = (attempts.get(key) || []).filter(time => now - time < 15 * 60 * 1000);
  if (recent.length >= 20) {
    return res.status(429).json({ message: "Too many attempts. Please try again in 15 minutes." });
  }
  recent.push(now);
  attempts.set(key, recent);
  next();
}

app.post("/api/auth/register", authRateLimit, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 60) {
      return res.status(400).json({ message: "Name must contain 2 to 60 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Enter a valid email address." });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ message: "Password must be at least 8 characters long." });
    }

    const users = readUsers();
    if (users.some(user => user.email === email)) {
      return res.status(409).json({ message: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: require("crypto").randomUUID(),
      name,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeUsers(users);

    req.session.user = { id: user.id, name: user.name, email: user.email };
    return res.status(201).json({ message: "Account created successfully.", user: req.session.user });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ message: "Unable to create account right now." });
  }
});

app.post("/api/auth/login", authRateLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = readUsers().find(item => item.email === email);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ message: "Could not start your session." });
      req.session.user = { id: user.id, name: user.name, email: user.email };
      return res.json({ message: "Login successful.", user: req.session.user });
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Unable to log in right now." });
  }
});

app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Could not log out." });
    res.clearCookie("irfan_portfolio_sid");
    res.json({ message: "Logged out successfully." });
  });
});

// Serve static assets and the public authentication pages, but do not expose
// the portfolio HTML directly through /index.html.
app.use(express.static(FRONTEND_DIR, { index: false }));

// The login page is always the first page visitors see.
app.get("/", (req, res) => res.sendFile(path.join(FRONTEND_DIR, "login.html")));

// The portfolio is available only after successful authentication.
app.get("/portfolio", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  return res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

// Also protect attempts to open the portfolio HTML directly.
app.get("/index.html", (req, res) => res.redirect("/portfolio"));

app.listen(PORT, () => {
  console.log(`Portfolio is running at http://localhost:${PORT}`);
});
