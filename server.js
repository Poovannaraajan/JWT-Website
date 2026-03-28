// server.js - Secure Online Examination System with JWT & Role-Based Access Control
// VITONLINE Examination Platform
// Manual JWT Implementation (without jsonwebtoken library)

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================================
// 5. USER DATABASE AND AUTHENTICATION
//    - Simulated user database with pre-registered users
//    - Each user has: password and role (STUDENT or FACULTY)
//    - In production, passwords would be hashed (bcrypt/argon2)
// =====================================================================
const users = {
    student1: { password: 'pass123', role: 'STUDENT', name: 'Rahul Sharma' },
    student2: { password: 'pass456', role: 'STUDENT', name: 'Priya Patel' },
    student3: { password: 'pass789', role: 'STUDENT', name: 'Arjun Nair' },
    faculty1: { password: 'faculty123', role: 'FACULTY', name: 'Dr. Ananya Verma' },
    faculty2: { password: 'faculty456', role: 'FACULTY', name: 'Prof. Rajesh Kumar' }
};

// PHASE 1: User Authentication
const authenticateUser = (username, password) => {
    if (users[username] && users[username].password === password) {
        return {
            success: true,
            role: users[username].role,
            name: users[username].name,
            message: 'Authentication Successful'
        };
    }
    return {
        success: false,
        message: 'Invalid username or password'
    };
};

// =====================================================================
// 2. HMAC-SHA256 SIGNATURE GENERATION
//    - Uses Node.js crypto module to generate HMAC-SHA256
//    - Secret key is used to sign the data (header.payload)
//    - Returns Base64URL encoded signature
// =====================================================================
const SECRET_KEY = 'VITOnlineExaminationSystemSecretKey2025';

// Base64URL encode (URL-safe Base64 without padding)
const base64UrlEncode = (data) => {
    let base64;
    if (Buffer.isBuffer(data)) {
        base64 = data.toString('base64');
    } else {
        base64 = Buffer.from(data).toString('base64');
    }
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

// Base64URL decode
const base64UrlDecode = (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding
    while (str.length % 4 !== 0) {
        str += '=';
    }
    return Buffer.from(str, 'base64').toString('utf8');
};

// HMAC-SHA256 Signature Generation
const generateSignature = (data) => {
    const hmac = crypto.createHmac('sha256', SECRET_KEY);
    hmac.update(data);
    const signature = hmac.digest(); // Returns Buffer
    return base64UrlEncode(signature);
};

// =====================================================================
// 1. JWT TOKEN GENERATION (HMAC-SHA256)
//    - Manually creates JWT with Header, Payload, and Signature
//    - Header specifies algorithm (HS256) and token type (JWT)
//    - Payload contains user claims: sub, role, name, iat, exp
//    - Signature = HMAC-SHA256(base64url(header).base64url(payload), secret)
//    - Returns complete JWT: header.payload.signature
// =====================================================================
const generateJWT = (username, role, name) => {
    // PHASE 2: Create Header
    const header = {
        alg: 'HS256',           // Algorithm: HMAC-SHA256
        typ: 'JWT'              // Token type: JSON Web Token
    };

    // PHASE 2: Create Payload with claims
    const payload = {
        sub: username,          // Subject (user identifier)
        role: role,             // User role (STUDENT/FACULTY)
        name: name,             // User display name
        iat: Date.now(),        // Issued at time (milliseconds)
        exp: Date.now() + 3600000  // Expiration (1 hour from now)
    };

    // Base64URL encode header and payload
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));

    // Generate HMAC-SHA256 signature over header.payload
    const signature = generateSignature(
        `${encodedHeader}.${encodedPayload}`
    );

    console.log(`[JWT] Token generated for ${username}`);
    console.log(`[JWT]   Header  : ${encodedHeader}`);
    console.log(`[JWT]   Payload : ${encodedPayload}`);
    console.log(`[JWT]   Signature: ${signature}`);

    // Return complete JWT: header.payload.signature
    return `${encodedHeader}.${encodedPayload}.${signature}`;
};

// =====================================================================
// 3. TOKEN VERIFICATION
//    - Splits token into header, payload, signature parts
//    - Recalculates HMAC-SHA256 signature and compares
//    - Checks token expiration time
//    - If signature mismatch → token tampered
//    - If expired → token expired
//    - Returns decoded payload if valid
// =====================================================================
const verifyToken = (token) => {
    const parts = token.split('.');

    // Check token structure (must have 3 parts)
    if (parts.length !== 3) {
        return { valid: false, error: 'Invalid token format' };
    }

    const [header, payload, signature] = parts;

    // Recalculate signature using HMAC-SHA256
    const expectedSignature = generateSignature(
        `${header}.${payload}`
    );

    // Compare signatures (timing-safe comparison)
    if (expectedSignature !== signature) {
        return { valid: false, error: 'Invalid signature - Token tampered' };
    }

    // Decode and check expiration
    const decodedPayload = JSON.parse(base64UrlDecode(payload));

    if (Date.now() > decodedPayload.exp) {
        return { valid: false, error: 'Token expired' };
    }

    return { valid: true, payload: decodedPayload };
};

// =====================================================================
// 4. ROLE-BASED ACCESS CONTROL (RBAC)
//    - Defines permissions for each role
//    - STUDENT: can view questions and submit answers
//    - FACULTY: can do everything students can + create exams,
//               view submissions, and manage results
//    - checkAuthorization() verifies if a role has the required permission
// =====================================================================
const rolePermissions = {
    STUDENT: ['VIEW_QUESTIONS', 'SUBMIT_ANSWER'],
    FACULTY: ['VIEW_QUESTIONS', 'SUBMIT_ANSWER', 'CREATE_EXAM',
              'VIEW_SUBMISSIONS', 'MANAGE_RESULTS', 'VIEW_EXAMS']
};

const checkAuthorization = (userRole, requestedEndpoint) => {
    const allowedEndpoints = rolePermissions[userRole];
    if (allowedEndpoints?.includes(requestedEndpoint)) {
        console.log(`[RBAC] ✓ Access GRANTED - ${userRole} can access ${requestedEndpoint}`);
        return true;
    } else {
        console.log(`[RBAC] ✗ Access DENIED - ${userRole} cannot access ${requestedEndpoint}`);
        return false;
    }
};

// =====================================================================
// MIDDLEWARE: Token Authentication
//    - Extracts JWT from Authorization: Bearer <token> header
//    - Verifies token using verifyToken() (step 3)
//    - Attaches decoded user info to req.user
// =====================================================================
const authenticateTokenMiddleware = (req, res, next) => {
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
        console.log(`[AUTH] Access DENIED - Token blacklisted | ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: 'Access Denied: Token has been invalidated (logged out)',
            code: 'TOKEN_BLACKLISTED'
        });
    }

    // PHASE 3: Verify the token (signature + expiration)
    const result = verifyToken(token);

    if (!result.valid) {
        console.log(`[AUTH] Access DENIED - ${result.error} | ${req.method} ${req.path}`);
        const status = result.error.includes('expired') ? 401 : 403;
        return res.status(status).json({
            success: false,
            error: `Access Denied: ${result.error}`,
            code: result.error.includes('expired') ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID'
        });
    }

    req.user = result.payload;
    console.log(`[AUTH] Access GRANTED - User: ${result.payload.name} (${result.payload.role}) | ${req.method} ${req.path}`);
    next();
};

// MIDDLEWARE: Role-Based Authorization
const authorizeRole = (requiredPermission) => {
    return (req, res, next) => {
        // PHASE 4: Check role-based authorization
        if (!checkAuthorization(req.user.role, requiredPermission)) {
            return res.status(403).json({
                success: false,
                error: `Access Denied: ${req.user.role} does not have ${requiredPermission} permission`,
                code: 'INSUFFICIENT_ROLE'
            });
        }
        next();
    };
};

// Token blacklist (for logout)
const tokenBlacklist = new Set();

// ======================== In-Memory Data Store ========================

let exams = [
    {
        id: 1,
        title: 'Cryptography Mid-Term',
        createdBy: 'faculty1',
        facultyName: 'Dr. Ananya Verma',
        questions: [
            { id: 1, question: 'What does AES stand for?', options: ['Advanced Encryption Standard', 'Advanced Electronic System', 'Automated Encryption Service', 'Applied Encryption Suite'], correct: 0 },
            { id: 2, question: 'Which key length does AES-256 use?', options: ['128 bits', '192 bits', '256 bits', '512 bits'], correct: 2 },
            { id: 3, question: 'What is the purpose of HMAC?', options: ['Encryption', 'Message Integrity', 'Key Exchange', 'Compression'], correct: 1 }
        ],
        createdAt: new Date().toISOString()
    }
];

let submissions = [];

// ======================== API Routes ========================

// POST /api/login — PHASE 1: Authenticate user and generate JWT
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            error: 'Username and password are required'
        });
    }

    // PHASE 1: Authenticate user against database
    const authResult = authenticateUser(username, password);

    if (!authResult.success) {
        console.log(`[LOGIN] FAILED - Invalid credentials for: ${username}`);
        return res.status(401).json({
            success: false,
            error: authResult.message
        });
    }

    console.log(`[LOGIN] SUCCESS - User: ${authResult.name} | Role: ${authResult.role}`);

    // PHASE 2: Generate JWT token with role
    const token = generateJWT(username, authResult.role, authResult.name);

    // Decode token to show details in response
    const decoded = verifyToken(token);

    res.json({
        success: true,
        message: `Welcome, ${authResult.name}! ${authResult.message}`,
        token: token,
        user: {
            username: username,
            name: authResult.name,
            role: authResult.role
        },
        tokenInfo: {
            issuedAt: new Date(decoded.payload.iat).toISOString(),
            expiresAt: new Date(decoded.payload.exp).toISOString(),
            algorithm: 'HS256 (HMAC-SHA256)'
        }
    });
});

// POST /api/logout — Invalidate token
app.post('/api/logout', authenticateTokenMiddleware, (req, res) => {
    const token = req.headers['authorization'].split(' ')[1];
    tokenBlacklist.add(token);
    console.log(`[LOGOUT] User: ${req.user.name} | Token blacklisted`);
    res.json({ success: true, message: 'Logged out successfully. Token invalidated.' });
});

// GET /api/profile — View profile (any authenticated user)
app.get('/api/profile', authenticateTokenMiddleware, (req, res) => {
    res.json({
        success: true,
        user: {
            username: req.user.sub,
            name: req.user.name,
            role: req.user.role
        }
    });
});

// ======================== Student Routes ========================
// Middleware chain: authenticateTokenMiddleware (step 3) → authorizeRole (step 4)

// GET /api/student/exams — View available exams (STUDENT — VIEW_QUESTIONS)
app.get('/api/student/exams', authenticateTokenMiddleware, authorizeRole('VIEW_QUESTIONS'), (req, res) => {
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

// GET /api/student/exams/:id — View exam questions (STUDENT — VIEW_QUESTIONS)
app.get('/api/student/exams/:id', authenticateTokenMiddleware, authorizeRole('VIEW_QUESTIONS'), (req, res) => {
    const exam = exams.find(e => e.id === parseInt(req.params.id));

    if (!exam) {
        return res.status(404).json({ success: false, error: 'Exam not found' });
    }

    // Send questions WITHOUT correct answers (security)
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

// POST /api/student/submit — Submit exam answers (STUDENT — SUBMIT_ANSWER)
app.post('/api/student/submit', authenticateTokenMiddleware, authorizeRole('SUBMIT_ANSWER'), (req, res) => {
    const { examId, answers } = req.body;

    if (!examId || !answers) {
        return res.status(400).json({ success: false, error: 'examId and answers are required' });
    }

    const exam = exams.find(e => e.id === examId);
    if (!exam) {
        return res.status(404).json({ success: false, error: 'Exam not found' });
    }

    // Check if already submitted
    const existing = submissions.find(s => s.studentUsername === req.user.sub && s.examId === examId);
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
        studentUsername: req.user.sub,
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
// Middleware chain: authenticateTokenMiddleware (step 3) → authorizeRole (step 4)

// POST /api/faculty/exams — Create a new exam (FACULTY — CREATE_EXAM)
app.post('/api/faculty/exams', authenticateTokenMiddleware, authorizeRole('CREATE_EXAM'), (req, res) => {
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
        createdBy: req.user.sub,
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

// GET /api/faculty/submissions — View all submissions (FACULTY — VIEW_SUBMISSIONS)
app.get('/api/faculty/submissions', authenticateTokenMiddleware, authorizeRole('VIEW_SUBMISSIONS'), (req, res) => {
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

// GET /api/faculty/results — View results summary (FACULTY — MANAGE_RESULTS)
app.get('/api/faculty/results', authenticateTokenMiddleware, authorizeRole('MANAGE_RESULTS'), (req, res) => {
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

// GET /api/faculty/exams — View all exams (FACULTY — VIEW_EXAMS)
app.get('/api/faculty/exams', authenticateTokenMiddleware, authorizeRole('VIEW_EXAMS'), (req, res) => {
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

// ======================== Demo: Access Denied Route ========================

app.get('/api/test/no-token', authenticateTokenMiddleware, (req, res) => {
    res.json({ message: 'You should not see this without a token' });
});

// ======================== Server Start ========================

app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('   VITONLINE Secure Examination System');
    console.log('   Manual JWT (HMAC-SHA256) + Role-Based Access Control');
    console.log('='.repeat(60));
    console.log(`\n[SERVER] Running on http://localhost:${PORT}`);
    console.log(`[SERVER] Secret Key: ${SECRET_KEY}`);
    console.log(`[SERVER] Token Expiry: 1 hour`);
    console.log('\n[SERVER] Registered Users:');
    Object.entries(users).forEach(([username, u]) => {
        console.log(`  - ${username} / ${u.password}  (${u.role}) — ${u.name}`);
    });
    console.log('\n[SERVER] Role Permissions:');
    Object.entries(rolePermissions).forEach(([role, perms]) => {
        console.log(`  ${role}: ${perms.join(', ')}`);
    });
    console.log('\n[SERVER] Waiting for requests...\n');
});
