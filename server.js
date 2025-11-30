const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session); // 🔥 New Library
const multer = require('multer');
const fs = require('fs');

// Environment variables configuration
dotenv.config();
const app = express();

// --- 1. MIDDLEWARE SETUP ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Ensure 'public/uploads' directory exists
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.static(path.join(__dirname, 'public')));

// --- 2. DATABASE CONFIGURATION ---
// Create a config object to share between DB connection and Session Store
const dbOptions = {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASS || "root",
    database: process.env.DB_NAME || "college_management",
    port: process.env.DB_PORT || 3306,
};

// Add SSL if on Cloud
if (process.env.DB_HOST) {
    dbOptions.ssl = { rejectUnauthorized: false };
}

// Create Database Connection
const db = mysql.createConnection(dbOptions);

db.connect((err) => {
    if (err) console.error("❌ Database connection failed:", err.message);
    else console.log("✅ Connected to MySQL database successfully");
});

// --- 3. SESSION SETUP (STORE IN DATABASE) ---
// 🔥 Yeh naya code hai: Session ab Database me save hoga, RAM me nahi.
const sessionStore = new MySQLStore(dbOptions);

app.set('trust proxy', 1); // Render ke liye zaroori

app.use(session({
    key: 'session_cookie_name',
    secret: 'campuscare_secret_key_secure_123',
    store: sessionStore, // 🔥 Database Store
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Compatibility ke liye false rakha hai
        maxAge: 24 * 60 * 60 * 1000 // 24 Hours
    }
}));

// --- 4. MULTER ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, 'public/uploads/'); },
    filename: function (req, file, cb) { cb(null, Date.now() + path.extname(file.originalname)); }
});
const upload = multer({ storage: storage });

// --- 5. AUTH MIDDLEWARE ---
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ message: 'Unauthorized: Please log in.' });
}
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).json({ message: 'Forbidden: Admin access required.' });
}

// ================= ROUTES =================

// LOGIN
app.post("/api/staff/login", (req, res) => {
    const { staffId, password } = req.body;
    db.query("SELECT * FROM staff_users WHERE staff_id = ? AND password = ?", [staffId, password], (err, results) => {
        if (err) return res.status(500).json({ message: "Database error" });
        if (results.length > 0) {
            req.session.user = { id: results[0].id, name: results[0].name, role: 'staff' };
            // Force save session
            req.session.save(err => {
                if(err) return res.status(500).json({message: "Session Error"});
                res.json({ success: true, user: results[0] });
            });
        } else res.status(401).json({ success: false, message: "Invalid Credentials" });
    });
});

app.post("/api/login", (req, res) => {
    const { email, password } = req.body;
    db.query("SELECT * FROM students WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ message: "Invalid credentials" });
        if (await bcrypt.compare(password, results[0].password_hash)) {
            req.session.user = { id: results[0].student_id, name: results[0].name, role: 'student' };
            req.session.save(err => {
                if(err) return res.status(500).json({message: "Session Error"});
                res.json({ message: "Login successful" });
            });
        } else res.status(401).json({ message: "Invalid credentials" });
    });
});

app.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body;
    db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ message: "Invalid credentials" });
        if (await bcrypt.compare(password, results[0].password_hash)) {
            req.session.user = { id: results[0].admin_id, name: results[0].name, role: 'admin' };
            req.session.save(err => {
                if(err) return res.status(500).json({message: "Session Error"});
                res.json({ message: "Login successful" });
            });
        } else res.status(401).json({ message: "Invalid credentials" });
    });
});

// REQUESTS
app.post("/api/requests", isAuthenticated, upload.single('image'), (req, res) => {
    const { service_type, building, floor, room, description } = req.body;
    const img = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO service_requests (student_id, service_type, building, floor, room, description, image_path) VALUES (?,?,?,?,?,?,?)", 
    [req.session.user.id, service_type, building, floor, room, description, img], (err) => {
        if(err) return res.status(500).json({message: "Error"});
        res.status(201).json({message: "Submitted"});
    });
});

app.get("/api/my-requests", isAuthenticated, (req, res) => {
    db.query("SELECT * FROM service_requests WHERE student_id = ? ORDER BY created_at DESC", [req.session.user.id], (err, results) => res.json(results));
});

// ADMIN
app.get("/api/admin/all-requests", isAuthenticated, isAdmin, (req, res) => {
    const query = `SELECT sr.*, s.name AS student_name, st.name AS staff_name FROM service_requests sr JOIN students s ON sr.student_id = s.student_id LEFT JOIN staff_users st ON sr.assigned_to = st.id ORDER BY sr.created_at DESC`;
    db.query(query, (err, results) => res.json(results));
});

app.get("/api/admin/staff-list", isAuthenticated, isAdmin, (req, res) => {
    db.query("SELECT id, name, staff_id FROM staff_users", (err, results) => res.json(results));
});

app.put("/api/admin/assign-task", isAuthenticated, isAdmin, (req, res) => {
    const { requestId, staffId } = req.body;
    db.query("UPDATE service_requests SET assigned_to = ?, status = 'Assigned', updated_at = NOW() WHERE request_id = ?", [staffId, requestId], (err) => {
        res.json({ message: "Task Assigned" });
    });
});

app.get("/api/admin/stats", isAuthenticated, isAdmin, (req, res) => {
    const query = `SELECT (SELECT COUNT(*) FROM service_requests) AS total_requests, (SELECT COUNT(*) FROM service_requests WHERE status = 'Pending') AS pending_requests, (SELECT COUNT(*) FROM service_requests WHERE status = 'Completed') AS completed_requests, (SELECT COUNT(*) FROM students) AS active_users`;
    db.query(query, (err, results) => res.json(results[0]));
});

app.put("/api/admin/update-status", isAuthenticated, isAdmin, (req, res) => {
    const { requestId, status } = req.body;
    const query = "UPDATE service_requests SET status = ?, updated_at = NOW() WHERE request_id = ?";
    db.query(query, [status, requestId], (err) => {
        if(err) return res.status(500).json({message: "Error"});
        res.json({ message: "Updated" });
    });
});

// STAFF
app.get("/api/staff/my-tasks", isAuthenticated, (req, res) => {
    const query = `SELECT sr.*, s.name as student_name FROM service_requests sr JOIN students s ON sr.student_id = s.student_id WHERE sr.assigned_to = ? AND sr.status IN ('Assigned', 'In Progress', 'Work Done') ORDER BY sr.created_at DESC`;
    db.query(query, [req.session.user.id], (err, results) => res.json(results));
});

app.get("/api/staff/history", isAuthenticated, (req, res) => {
    const query = `SELECT sr.*, s.name as student_name FROM service_requests sr JOIN students s ON sr.student_id = s.student_id WHERE sr.assigned_to = ? AND sr.status IN ('Completed', 'Cancelled', 'Rejected') ORDER BY sr.updated_at DESC`;
    db.query(query, [req.session.user.id], (err, results) => res.json(results));
});

app.put("/api/staff/update-status", isAuthenticated, upload.single('proofImage'), (req, res) => {
    const { requestId, status, reason } = req.body;
    const proofPath = req.file ? `/uploads/${req.file.filename}` : null;
    let newStatus = (status === 'Completed') ? 'Work Done' : status;

    let query = "UPDATE service_requests SET status = ?";
    let params = [newStatus];

    if (proofPath) { query += ", staff_proof_image = ?"; params.push(proofPath); }
    if (reason) { query += ", rejection_reason = ?"; params.push(reason); }
    
    query += ", updated_at = NOW() WHERE request_id = ? AND assigned_to = ?";
    params.push(requestId, req.session.user.id);

    db.query(query, params, (err) => {
        if(err) return res.status(500).json({message: "Error"});
        res.json({ message: "Status Updated" });
    });
});

// USER NOTIFICATIONS
app.get("/api/my-notifications", isAuthenticated, (req, res) => {
    db.query("SELECT * FROM service_requests WHERE student_id = ? ORDER BY updated_at DESC LIMIT 20", [req.session.user.id], (err, results) => {
        res.json(results);
    });
});

// COMMON
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        res.json({ message: "Logged out" });
    });
});
app.get('/api/user', isAuthenticated, (req, res) => { res.json(req.session.user); });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));