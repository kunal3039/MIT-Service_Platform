const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');

// Environment variables configuration
dotenv.config();
const app = express();

// --- 1. MIDDLEWARE SETUP ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Render Proxy Trust (Fix for Logout Issue)
app.set('trust proxy', 1);

// Ensure 'public/uploads' directory exists
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve Static Files
app.use(express.static(path.join(__dirname, 'public')));

// ==================================================
// 🔥 FINAL FIX: SESSION CONFIGURATION 🔥
// ==================================================
app.use(session({
    secret: 'campuscare_secret_key_secure_123',
    resave: true,               // Force save session
    saveUninitialized: true,    // Save new sessions
    cookie: { 
        secure: false,          // ⚠️ FALSE: Taaki browser cookie reject na kare
        maxAge: 24 * 60 * 60 * 1000 // 24 Hours
    }
}));
// ==================================================


// --- 2. MULTER CONFIGURATION (IMAGE UPLOAD) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- 3. DATABASE CONNECTION (Auto SSL) ---
const dbConfig = {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASS || "root",
    database: process.env.DB_NAME || "college_management",
    port: process.env.DB_PORT || 3306
};

// Add SSL if running on Cloud
if (process.env.DB_HOST) {
    dbConfig.ssl = {
        rejectUnauthorized: false
    };
}

const db = mysql.createConnection(dbConfig);

db.connect((err) => {
    if (err) {
        console.error("❌ Database connection failed:", err.message);
    } else {
        console.log("✅ Connected to MySQL database successfully");
    }
});

// --- 4. AUTH MIDDLEWARE FUNCTIONS ---
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ message: 'Unauthorized: Please log in.' });
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).json({ message: 'Forbidden: Admin access required.' });
}

// ==================================================
// ==================== ROUTES ======================
// ==================================================

// --- A. LOGIN ROUTES ---

// 1. STAFF LOGIN
app.post("/api/staff/login", (req, res) => {
    const { staffId, password } = req.body;
    const query = "SELECT * FROM staff_users WHERE staff_id = ? AND password = ?";
    
    db.query(query, [staffId, password], (err, results) => {
        if (err) return res.status(500).json({ message: "Database error" });
        
        if (results.length > 0) {
            const user = results[0];
            req.session.user = { id: user.id, name: user.name, role: 'staff' };
            res.json({ success: true, message: "Login Successful", user: user });
        } else {
            res.status(401).json({ success: false, message: "Invalid Staff ID or Password" });
        }
    });
});

// 2. STUDENT LOGIN
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;
    const query = "SELECT * FROM students WHERE email = ?";
    db.query(query, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ message: "Invalid credentials" });
        
        const user = results[0];
        const match = await bcrypt.compare(password, user.password_hash);
        
        if (match) {
            req.session.user = { id: user.student_id, name: user.name, email: user.email, role: 'student' };
            res.json({ message: "Login successful", name: user.name });
        } else {
            res.status(401).json({ message: "Invalid credentials" });
        }
    });
});

// 3. ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body;
    const query = "SELECT * FROM admins WHERE email = ?";
    db.query(query, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ message: "Invalid admin credentials" });
        
        const admin = results[0];
        const match = await bcrypt.compare(password, admin.password_hash);
        
        if (match) {
            req.session.user = { id: admin.admin_id, name: admin.name, email: admin.email, role: 'admin' };
            res.json({ message: "Admin login successful", name: admin.name });
        } else {
            res.status(401).json({ message: "Invalid admin credentials" });
        }
    });
});

// --- B. STUDENT REQUEST ROUTES ---

// 4. SUBMIT NEW REQUEST
app.post("/api/requests", isAuthenticated, upload.single('image'), (req, res) => {
    const { service_type, building, floor, room, description } = req.body;
    const student_id = req.session.user.id;
    const image_path = req.file ? `/uploads/${req.file.filename}` : null;

    const query = `INSERT INTO service_requests (student_id, service_type, building, floor, room, description, image_path) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    
    db.query(query, [student_id, service_type, building, floor, room, description, image_path], (err, result) => {
        if (err) return res.status(500).json({ message: "Failed to submit request." });
        res.status(201).json({ message: "Request submitted successfully!", requestId: result.insertId });
    });
});

// 5. GET MY REQUESTS
app.get("/api/my-requests", isAuthenticated, (req, res) => {
    const student_id = req.session.user.id;
    const query = "SELECT * FROM service_requests WHERE student_id = ? ORDER BY created_at DESC";
    db.query(query, [student_id], (err, results) => res.json(results));
});

// --- C. ADMIN DASHBOARD ROUTES ---

// 6. GET ALL REQUESTS
app.get("/api/admin/all-requests", isAuthenticated, isAdmin, (req, res) => {
    const query = `
        SELECT sr.*, s.name AS student_name, st.name AS staff_name 
        FROM service_requests sr 
        JOIN students s ON sr.student_id = s.student_id
        LEFT JOIN staff_users st ON sr.assigned_to = st.id
        ORDER BY sr.created_at DESC`;
        
    db.query(query, (err, results) => res.json(results));
});

// 7. GET STAFF LIST
app.get("/api/admin/staff-list", isAuthenticated, isAdmin, (req, res) => {
    db.query("SELECT id, name, staff_id FROM staff_users", (err, results) => res.json(results));
});

// 8. ASSIGN TASK
app.put("/api/admin/assign-task", isAuthenticated, isAdmin, (req, res) => {
    const { requestId, staffId } = req.body;
    db.query("UPDATE service_requests SET assigned_to = ?, status = 'Assigned', updated_at = NOW() WHERE request_id = ?", [staffId, requestId], (err, result) => {
        if (err) return res.status(500).json({ message: "Error assigning task" });
        res.json({ message: "Task Assigned Successfully" });
    });
});

// 9. ADMIN STATS
app.get("/api/admin/stats", isAuthenticated, isAdmin, (req, res) => {
    const query = `
        SELECT
            (SELECT COUNT(*) FROM service_requests) AS total_requests,
            (SELECT COUNT(*) FROM service_requests WHERE status = 'Pending') AS pending_requests,
            (SELECT COUNT(*) FROM service_requests WHERE status = 'Completed') AS completed_requests,
            (SELECT COUNT(*) FROM students) AS active_users
    `;
    db.query(query, (err, results) => res.json(results[0]));
});

// 10. ADMIN VERIFY & COMPLETE
app.put("/api/admin/update-status", isAuthenticated, isAdmin, (req, res) => {
    const { requestId, status } = req.body;
    const query = "UPDATE service_requests SET status = ?, updated_at = NOW() WHERE request_id = ?";
    db.query(query, [status, requestId], (err) => {
        if(err) return res.status(500).json({message: "Error"});
        res.json({ message: "Verified & Completed" });
    });
});

// --- D. STAFF ROUTES ---

// 11. GET ACTIVE TASKS
app.get("/api/staff/my-tasks", isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'staff') return res.status(403).json({ message: "Not authorized" });
    const query = `
        SELECT sr.*, s.name as student_name 
        FROM service_requests sr
        JOIN students s ON sr.student_id = s.student_id
        WHERE sr.assigned_to = ? AND sr.status IN ('Assigned', 'In Progress', 'Work Done')
        ORDER BY sr.created_at DESC`;
    db.query(query, [req.session.user.id], (err, results) => res.json(results));
});

// 12. GET HISTORY
app.get("/api/staff/history", isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'staff') return res.status(403).json({ message: "Not authorized" });
    const query = `
        SELECT sr.*, s.name as student_name 
        FROM service_requests sr
        JOIN students s ON sr.student_id = s.student_id
        WHERE sr.assigned_to = ? AND sr.status IN ('Completed', 'Cancelled', 'Rejected')
        ORDER BY sr.updated_at DESC`;
    db.query(query, [req.session.user.id], (err, results) => res.json(results));
});

// 13. UPDATE STATUS (STAFF)
app.put("/api/staff/update-status", isAuthenticated, upload.single('proofImage'), (req, res) => {
    const { requestId, status, reason } = req.body;
    const proofPath = req.file ? `/uploads/${req.file.filename}` : null;
    
    let newStatus = status;
    if (status === 'Completed') newStatus = 'Work Done';

    let query = "UPDATE service_requests SET status = ?";
    let params = [newStatus];

    if (proofPath) { query += ", staff_proof_image = ?"; params.push(proofPath); }
    if (reason) { query += ", rejection_reason = ?"; params.push(reason); }
    
    query += ", updated_at = NOW() WHERE request_id = ? AND assigned_to = ?";
    params.push(requestId, req.session.user.id);

    db.query(query, params, (err, result) => {
        if (err) return res.status(500).json({ message: "Error updating status" });
        res.json({ message: "Status Updated Successfully", image_url: proofPath });
    });
});

// --- E. USER NOTIFICATIONS ---

// 16. GET NOTIFICATIONS
app.get("/api/my-notifications", isAuthenticated, (req, res) => {
    const query = "SELECT * FROM service_requests WHERE student_id = ? ORDER BY updated_at DESC LIMIT 20";
    db.query(query, [req.session.user.id], (err, results) => {
        if (err) return res.status(500).json({ message: "Database Error" });
        res.json(results);
    });
});

// --- F. COMMON ROUTES ---

// 14. LOGOUT
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: "Logged out successfully" });
});

// 15. GET USER INFO
app.get('/api/user', isAuthenticated, (req, res) => {
    res.json(req.session.user);
});

// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));