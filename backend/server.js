const express = require("express");
const cors = require("cors");
const path = require("path");
const Database = require("better-sqlite3");
require("dotenv").config({
    path: path.join(__dirname, ".env")
});

const app = express();
const PORT = process.env.PORT || 5000;

// --------------------
// Middleware
// --------------------
app.use(cors());
app.use(express.json());

// --------------------
// Database
// --------------------
const db = new Database(path.join(__dirname, "smart-cram.db"));

db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cheatsheets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS flashcards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
`);

// --------------------
// Authentication - Register
// --------------------
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "development-secret-change-me";

app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email and password are required"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 6 characters"
            });
        }

        const existingUser = db
            .prepare("SELECT id FROM users WHERE email = ?")
            .get(email.toLowerCase().trim());

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "Email is already registered"
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = db
            .prepare(`
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
            `)
            .run(
                name.trim(),
                email.toLowerCase().trim(),
                passwordHash
            );

        const token = jwt.sign(
            {
                userId: result.lastInsertRowid,
                email: email.toLowerCase().trim()
            },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(201).json({
            success: true,
            message: "Registration successful",
            token,
            user: {
                id: result.lastInsertRowid,
                name: name.trim(),
                email: email.toLowerCase().trim()
            }
        });

    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            success: false,
            message: "Server error during registration"
        });
    }
});


// --------------------
// Authentication - Login
// --------------------
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        const user = db
            .prepare("SELECT * FROM users WHERE email = ?")
            .get(email.toLowerCase().trim());

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const passwordValid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            success: false,
            message: "Server error during login"
        });
    }
});

// --------------------
// JWT Authentication Middleware
// --------------------
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Authentication token required"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token"
        });
    }
}

// --------------------
// Protected Test Route
// --------------------
app.get("/api/auth/me", authenticateToken, (req, res) => {
    const user = db
        .prepare("SELECT id, name, email, created_at FROM users WHERE id = ?")
        .get(req.user.userId);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found"
        });
    }

    res.json({
        success: true,
        user
    });
});

// --------------------
// Cheatsheets - Get all
// --------------------
app.get("/api/cheatsheets", authenticateToken, (req, res) => {
    try {
        const cheatsheets = db
            .prepare(`
                SELECT id, title, content, created_at, updated_at
                FROM cheatsheets
                WHERE user_id = ?
                ORDER BY updated_at DESC
            `)
            .all(req.user.userId);

        res.json({
            success: true,
            cheatsheets
        });

    } catch (error) {
        console.error("Get cheatsheets error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load cheatsheets"
        });
    }
});

// --------------------
// Cheatsheets - Create
// --------------------
app.post("/api/cheatsheets", authenticateToken, (req, res) => {
    try {
        const { title, content } = req.body;

        if (!title || !content) {
            return res.status(400).json({
                success: false,
                message: "Title and content are required"
            });
        }

        const result = db
            .prepare(`
                INSERT INTO cheatsheets (user_id, title, content)
                VALUES (?, ?, ?)
            `)
            .run(
                req.user.userId,
                title.trim(),
                content
            );

        const cheatsheet = db
            .prepare(`
                SELECT id, title, content, created_at, updated_at
                FROM cheatsheets
                WHERE id = ?
            `)
            .get(result.lastInsertRowid);

        res.status(201).json({
            success: true,
            message: "Cheatsheet created",
            cheatsheet
        });

    } catch (error) {
        console.error("Create cheatsheet error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to create cheatsheet"
        });
    }
});

// --------------------
// Cheatsheets - Update
// --------------------
app.put("/api/cheatsheets/:id", authenticateToken, (req, res) => {
    try {
        const { title, content } = req.body;
        const cheatsheetId = req.params.id;

        if (!title || !content) {
            return res.status(400).json({
                success: false,
                message: "Title and content are required"
            });
        }

        const existing = db
            .prepare(`
                SELECT id
                FROM cheatsheets
                WHERE id = ? AND user_id = ?
            `)
            .get(cheatsheetId, req.user.userId);

        if (!existing) {
            return res.status(404).json({
                success: false,
                message: "Cheatsheet not found"
            });
        }

        db.prepare(`
            UPDATE cheatsheets
            SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        `).run(
            title.trim(),
            content,
            cheatsheetId,
            req.user.userId
        );

        const updated = db
            .prepare(`
                SELECT id, title, content, created_at, updated_at
                FROM cheatsheets
                WHERE id = ?
            `)
            .get(cheatsheetId);

        res.json({
            success: true,
            message: "Cheatsheet updated",
            cheatsheet: updated
        });

    } catch (error) {
        console.error("Update cheatsheet error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to update cheatsheet"
        });
    }
});

// --------------------
// Cheatsheets - Delete
// --------------------
app.delete("/api/cheatsheets/:id", authenticateToken, (req, res) => {
    try {
        const cheatsheetId = req.params.id;

        const result = db
            .prepare(`
                DELETE FROM cheatsheets
                WHERE id = ? AND user_id = ?
            `)
            .run(cheatsheetId, req.user.userId);

        if (result.changes === 0) {
            return res.status(404).json({
                success: false,
                message: "Cheatsheet not found"
            });
        }

        res.json({
            success: true,
            message: "Cheatsheet deleted"
        });

    } catch (error) {
        console.error("Delete cheatsheet error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to delete cheatsheet"
        });
    }
});

// --------------------
// Health check
// --------------------
app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        message: "Smart Cram backend is running!",
        database: "connected"
    });
});

// --------------------
// Start server
// --------------------
app.listen(PORT, () => {
    console.log(`Smart Cram backend running on port ${PORT}`);
    console.log("SQLite database connected");
});