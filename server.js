// server.js - Secure Online Examination System with JWT & Role-Based Access Control
// VITONLINE Examination Platform

const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// JWT Secret Key (in production, use environment variable)
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = '1h';

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// ======================== In-Memory Data Store ========================

// =====================================================================
// 5. USER DATABASE AND AUTHENTICATION
//    - In-memory user database with pre-registered users
//    - Each user has: id, username, password, role, name
//    - Roles are either 'faculty' or 'student'
//    - In production, this would be a real database with hashed passwords
// =====================================================================
const users = [
    { id: 1, username: 'faculty1', password: 'faculty123', role: 'faculty', name: 'Dr. Ananya Verma' },
    { id: 2, username: 'faculty2', password: 'faculty456', role: 'faculty', name: 'Prof. Rajesh Kumar' },
    { id: 3, username: 'student1', password: 'student123', role: 'student', name: 'Rahul Sharma' },
    { id: 4, username: 'student2', password: 'student456', role: 'student', name: 'Priya Patel' },
    { id: 5, username: 'student3', password: 'student789', role: 'student', name: 'Arjun Nair' }
];

// Exams created by faculty
let exams = [
    {
        id: 1,
        title: 'Cryptography Mid-Term',
        createdBy: 1,
        facultyName: 'Dr. Ananya Verma',
        questions: [
            { id: 1, question: 'What does AES stand for?', options: ['Advanced Encryption Standard', 'Advanced Electronic System', 'Automated Encryption Service', 'Applied Encryption Suite'], correct: 0 },
            { id: 2, question: 'Which key length does AES-256 use?', options: ['128 bits', '192 bits', '256 bits', '512 bits'], correct: 2 },
            { id: 3, question: 'What is the purpose of HMAC?', options: ['Encryption', 'Message Integrity', 'Key Exchange', 'Compression'], correct: 1 }
        ],
        createdAt: new Date().toISOString()
    }
];

// Student submissions
let submissions = [];

// Token blacklist (for logout)
const tokenBlacklist = new Set();

// ======================== Middleware Functions ========================

// =====================================================================
// 3. TOKEN VERIFICATION (authenticateToken middleware)
//    - Extracts JWT from 'Authorization: Bearer <token>' header
//    - Checks if token is missing → 401 TOKEN_MISSING
//    - Checks if token is blacklisted (logged out) → 401 TOKEN_BLACKLISTED
//    - Verifies the HMAC-SHA256 signature using jwt.verify()
//    - Checks if token is expired → 401 TOKEN_EXPIRED
//    - Checks if signature is invalid → 403 TOKEN_INVALID
//    - If valid → decodes payload and attaches user info to req.user
//    - This middleware is applied to ALL protected routes
// =====================================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        console.log(`[AUTH] Access DENIED - No token provided | ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: 'Access Denied: No token provided',
            code: 'TOKEN_MISSING'
        });
    }

    // Check if token is blacklisted (logged out)
    if (tokenBlacklist.has(token)) {
        console.log(`[AUTH] Access DENIED - Token blacklisted (logged out) | ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: 'Access Denied: Token has been invalidated (logged out)',
            code: 'TOKEN_BLACKLISTED'
        });
    }

    // jwt.verify() internally validates the HMAC-SHA256 signature
    // It recomputes HMAC-SHA256(base64(header) + "." + base64(payload), JWT_SECRET)
    // and compares it with the signature portion of the token
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                console.log(`[AUTH] Access DENIED - Token expired | ${req.method} ${req.path}`);
                return res.status(401).json({
                    success: false,
                    error: 'Access Denied: Token has expired',
                    code: 'TOKEN_EXPIRED'
                });
            }
            console.log(`[AUTH] Access DENIED - Invalid token | ${req.method} ${req.path}`);
            return res.status(403).json({
                success: false,
                error: 'Access Denied: Invalid token',
                code: 'TOKEN_INVALID'
            });
        }

        req.user = decoded;
        console.log(`[AUTH] Access GRANTED - User: ${decoded.name} (${decoded.role}) | ${req.method} ${req.path}`);
        next();
    });
}

// =====================================================================
// 4. ROLE-BASED ACCESS CONTROL (RBAC) (authorizeRole middleware)
//    - Takes allowed roles as arguments (e.g., 'student' or 'faculty')
//    - Checks if the authenticated user's role (from JWT payload) matches
//    - If role doesn't match → 403 INSUFFICIENT_ROLE
//    - If role matches → allows request to proceed
//    - Usage: authorizeRole('student') or authorizeRole('faculty')
//    - Applied AFTER authenticateToken in the middleware chain
// =====================================================================
function authorizeRole(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            console.log(`[AUTHZ] FORBIDDEN - User: ${req.user.name} (${req.user.role}) tried to access ${req.path} | Required: ${allowedRoles.join(', ')}`);
            return res.status(403).json({
                success: false,
                error: `Access Denied: Requires ${allowedRoles.join(' or ')} role. Your role: ${req.user.role}`,
                code: 'INSUFFICIENT_ROLE'
            });
        }
        next();
    };
}

// ======================== Auth Routes ========================

// =====================================================================
// 5. USER AUTHENTICATION (Login Route)
//    - Receives username and password from client
//    - Looks up user in the database (users array)
//    - If credentials invalid → 401 Unauthorized
//    - If valid → proceeds to JWT Token Generation (below)
// =====================================================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            error: 'Username and password are required'
        });
    }

    // 5. USER AUTHENTICATION - Verify credentials against the user database
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
        console.log(`[LOGIN] FAILED - Invalid credentials for username: ${username}`);
        return res.status(401).json({
            success: false,
            error: 'Invalid username or password'
        });
    }

    // =====================================================================
    // 1. JWT TOKEN GENERATION (with Role embedded in payload)
    //    - Payload contains: user id, username, name, role, issued-at time
    //    - The 'role' field is critical for RBAC (step 4)
    // =====================================================================
    const payload = {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role,           // <-- Role embedded in JWT for RBAC
        iat: Math.floor(Date.now() / 1000)
    };

    // =====================================================================
    // 2. HMAC-SHA256 SIGNATURE GENERATION
    //    - jwt.sign() creates the token: Header.Payload.Signature
    //    - Header:    {"alg": "HS256", "typ": "JWT"} → Base64 encoded
    //    - Payload:   {id, username, name, role, iat, exp} → Base64 encoded
    //    - Signature: HMAC-SHA256(base64(header) + "." + base64(payload), JWT_SECRET)
    //    - The secret key (JWT_SECRET) is a 256-bit random key
    //    - expiresIn adds 'exp' claim to payload (1 hour from now)
    // =====================================================================
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

    // Decode to show token details
    const decoded = jwt.decode(token);

    console.log(`[LOGIN] SUCCESS - User: ${user.name} | Role: ${user.role} | Token issued`);

    res.json({
        success: true,
        message: `Welcome, ${user.name}! Login successful.`,
        token: token,
        user: {
            id: user.id,
            name: user.name,
            role: user.role
        },
        tokenInfo: {
            issuedAt: new Date(decoded.iat * 1000).toISOString(),
            expiresAt: new Date(decoded.exp * 1000).toISOString(),
            algorithm: 'HS256'
        }
    });
});

// POST /api/logout - Invalidate token
app.post('/api/logout', authenticateToken, (req, res) => {
    const token = req.headers['authorization'].split(' ')[1];
    tokenBlacklist.add(token);
    console.log(`[LOGOUT] User: ${req.user.name} | Token blacklisted`);
    res.json({ success: true, message: 'Logged out successfully. Token invalidated.' });
});

// GET /api/profile - View own profile (any authenticated user)
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            name: req.user.name,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// ======================== Student Routes ========================
// These routes use BOTH middlewares in chain:
//   authenticateToken → (3. Token Verification)
//   authorizeRole('student') → (4. RBAC - only students allowed)

// GET /api/student/exams - View available exams (STUDENT ONLY)
app.get('/api/student/exams', authenticateToken, authorizeRole('student'), (req, res) => {
    const examList = exams.map(e => ({
        id: e.id,
        title: e.title,
        facultyName: e.facultyName,
        questionCount: e.questions.length,
        createdAt: e.createdAt
    }));

    res.json({
        success: true,
        message: `Found ${examList.length} exam(s) available`,
        exams: examList
    });
});

// GET /api/student/exams/:id - View exam questions (STUDENT ONLY)
app.get('/api/student/exams/:id', authenticateToken, authorizeRole('student'), (req, res) => {
    const exam = exams.find(e => e.id === parseInt(req.params.id));

    if (!exam) {
        return res.status(404).json({ success: false, error: 'Exam not found' });
    }

    // Send questions without correct answers
    const questions = exam.questions.map(q => ({
        id: q.id,
        question: q.question,
        options: q.options
    }));

    res.json({
        success: true,
        exam: {
            id: exam.id,
            title: exam.title,
            facultyName: exam.facultyName,
            questions: questions
        }
    });
});

// POST /api/student/submit - Submit exam answers (STUDENT ONLY)
app.post('/api/student/submit', authenticateToken, authorizeRole('student'), (req, res) => {
    const { examId, answers } = req.body;

    if (!examId || !answers) {
        return res.status(400).json({ success: false, error: 'examId and answers are required' });
    }

    const exam = exams.find(e => e.id === examId);
    if (!exam) {
        return res.status(404).json({ success: false, error: 'Exam not found' });
    }

    // Check if already submitted
    const existing = submissions.find(s => s.studentId === req.user.id && s.examId === examId);
    if (existing) {
        return res.status(409).json({ success: false, error: 'You have already submitted answers for this exam' });
    }

    // Calculate score
    let score = 0;
    const totalQuestions = exam.questions.length;
    exam.questions.forEach(q => {
        if (answers[q.id] === q.correct) score++;
    });

    const submission = {
        id: submissions.length + 1,
        studentId: req.user.id,
        studentName: req.user.name,
        examId: examId,
        examTitle: exam.title,
        answers: answers,
        score: score,
        total: totalQuestions,
        percentage: ((score / totalQuestions) * 100).toFixed(1),
        submittedAt: new Date().toISOString()
    };

    submissions.push(submission);
    console.log(`[EXAM] Submission by ${req.user.name} for "${exam.title}" - Score: ${score}/${totalQuestions}`);

    res.json({
        success: true,
        message: 'Answers submitted successfully!',
        result: {
            examTitle: exam.title,
            score: score,
            total: totalQuestions,
            percentage: submission.percentage + '%',
            submittedAt: submission.submittedAt
        }
    });
});

// ======================== Faculty Routes ========================
// These routes use BOTH middlewares in chain:
//   authenticateToken → (3. Token Verification)
//   authorizeRole('faculty') → (4. RBAC - only faculty allowed)

// POST /api/faculty/exams - Create a new exam (FACULTY ONLY)
app.post('/api/faculty/exams', authenticateToken, authorizeRole('faculty'), (req, res) => {
    const { title, questions } = req.body;

    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'title and questions array are required'
        });
    }

    const exam = {
        id: exams.length + 1,
        title: title,
        createdBy: req.user.id,
        facultyName: req.user.name,
        questions: questions.map((q, i) => ({
            id: i + 1,
            question: q.question,
            options: q.options,
            correct: q.correct
        })),
        createdAt: new Date().toISOString()
    };

    exams.push(exam);
    console.log(`[EXAM] Created by ${req.user.name}: "${title}" with ${questions.length} questions`);

    res.status(201).json({
        success: true,
        message: `Exam "${title}" created successfully!`,
        exam: {
            id: exam.id,
            title: exam.title,
            questionCount: exam.questions.length,
            createdAt: exam.createdAt
        }
    });
});

// GET /api/faculty/submissions - View all submissions (FACULTY ONLY)
app.get('/api/faculty/submissions', authenticateToken, authorizeRole('faculty'), (req, res) => {
    res.json({
        success: true,
        message: `Total ${submissions.length} submission(s)`,
        submissions: submissions.map(s => ({
            id: s.id,
            studentName: s.studentName,
            examTitle: s.examTitle,
            score: `${s.score}/${s.total}`,
            percentage: s.percentage + '%',
            submittedAt: s.submittedAt
        }))
    });
});

// GET /api/faculty/results - View results summary (FACULTY ONLY)
app.get('/api/faculty/results', authenticateToken, authorizeRole('faculty'), (req, res) => {
    const results = {};

    submissions.forEach(s => {
        if (!results[s.examId]) {
            results[s.examId] = {
                examTitle: s.examTitle,
                totalSubmissions: 0,
                averageScore: 0,
                highestScore: 0,
                lowestScore: 100,
                students: []
            };
        }
        const r = results[s.examId];
        r.totalSubmissions++;
        r.averageScore += parseFloat(s.percentage);
        r.highestScore = Math.max(r.highestScore, parseFloat(s.percentage));
        r.lowestScore = Math.min(r.lowestScore, parseFloat(s.percentage));
        r.students.push({
            name: s.studentName,
            score: `${s.score}/${s.total}`,
            percentage: s.percentage + '%'
        });
    });

    // Calculate averages
    Object.values(results).forEach(r => {
        r.averageScore = (r.averageScore / r.totalSubmissions).toFixed(1) + '%';
        r.highestScore = r.highestScore.toFixed(1) + '%';
        r.lowestScore = r.lowestScore.toFixed(1) + '%';
    });

    res.json({
        success: true,
        results: Object.values(results)
    });
});

// GET /api/faculty/exams - View all exams (FACULTY ONLY)
app.get('/api/faculty/exams', authenticateToken, authorizeRole('faculty'), (req, res) => {
    res.json({
        success: true,
        exams: exams.map(e => ({
            id: e.id,
            title: e.title,
            facultyName: e.facultyName,
            questionCount: e.questions.length,
            createdAt: e.createdAt
        }))
    });
});

// ======================== Demo: Access Denied Routes ========================

// Route to test unauthorized access
app.get('/api/test/no-token', authenticateToken, (req, res) => {
    res.json({ message: 'You should not see this without a token' });
});

// ======================== Server Start ========================

app.listen(PORT, () => {
    console.log('='.repeat(55));
    console.log('   VITONLINE Secure Examination System');
    console.log('   JWT Authentication with Role-Based Access Control');
    console.log('='.repeat(55));
    console.log(`\n[SERVER] Running on http://localhost:${PORT}`);
    console.log(`[SERVER] JWT Secret: ${JWT_SECRET.substring(0, 16)}... (${JWT_SECRET.length * 4} bits)`);
    console.log(`[SERVER] Token Expiry: ${TOKEN_EXPIRY}`);
    console.log('\n[SERVER] Registered Users:');
    users.forEach(u => {
        console.log(`  - ${u.username} / ${u.password}  (${u.role}) — ${u.name}`);
    });
    console.log('\n[SERVER] API Endpoints:');
    console.log('  POST /api/login              — Authenticate & get JWT');
    console.log('  POST /api/logout             — Invalidate token');
    console.log('  GET  /api/profile            — View profile (any role)');
    console.log('  GET  /api/student/exams      — View exams (student)');
    console.log('  GET  /api/student/exams/:id  — View questions (student)');
    console.log('  POST /api/student/submit     — Submit answers (student)');
    console.log('  POST /api/faculty/exams      — Create exam (faculty)');
    console.log('  GET  /api/faculty/submissions— View submissions (faculty)');
    console.log('  GET  /api/faculty/results    — View results (faculty)');
    console.log('\n[SERVER] Waiting for requests...\n');
});
