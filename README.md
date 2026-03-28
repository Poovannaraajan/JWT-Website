# Secure Online Examination System using JWT with Role-Based Access

## Aim

To design and develop a secure web application for the VITONLINE examination system that implements JWT (JSON Web Token)-based authentication and role-based authorization to provide stateless session management. The system supports two user roles:

- **Students** — Can view exam questions and submit answers
- **Faculty** — Can create exams, view submissions, and manage results

Access is denied if the token is invalid, missing, expired, or does not match the required role.

---

## Algorithm

### Flow of Execution

```
Login → JWT Generation (with Role) → Token Usage → Token Verification → Role-Based Authorization → Access Control
```

### Step-by-Step Algorithm

**1. User Login & JWT Generation**
1. Client sends `POST /api/login` with `{username, password}`.
2. Server looks up user in the registered users database.
3. If credentials are invalid → return `401 Unauthorized`.
4. If valid → create JWT payload containing: `{id, username, name, role, iat}`.
5. Sign the payload using **HMAC-SHA256** with a 256-bit secret key.
6. Set token expiry to 1 hour.
7. Return the signed JWT token to the client.

**2. Token Storage & Transmission**
1. Client stores the JWT token in memory.
2. For every subsequent API request, client sends the token in the `Authorization: Bearer <token>` header.

**3. Token Verification Middleware (Every Protected Request)**
1. Extract token from the `Authorization` header.
2. If no token present → return `401 TOKEN_MISSING`.
3. If token is in the blacklist (logged out) → return `401 TOKEN_BLACKLISTED`.
4. Verify the token signature using the server's secret key.
5. If signature invalid → return `403 TOKEN_INVALID`.
6. If token expired → return `401 TOKEN_EXPIRED`.
7. If valid → decode payload and attach user info to the request.

**4. Role-Based Authorization Middleware**
1. After token verification, check if the user's role matches the required role for the endpoint.
2. Student-only endpoints: `/api/student/*` — require `role = "student"`.
3. Faculty-only endpoints: `/api/faculty/*` — require `role = "faculty"`.
4. If role mismatch → return `403 INSUFFICIENT_ROLE`.
5. If role matches → grant access and process the request.

**5. Protected Operations**

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/login` | POST | Public | Authenticate & receive JWT |
| `/api/logout` | POST | Any | Blacklist token |
| `/api/profile` | GET | Any | View own profile |
| `/api/student/exams` | GET | Student | View available exams |
| `/api/student/exams/:id` | GET | Student | View exam questions |
| `/api/student/submit` | POST | Student | Submit exam answers |
| `/api/faculty/exams` | POST | Faculty | Create new exam |
| `/api/faculty/exams` | GET | Faculty | View all exams |
| `/api/faculty/submissions` | GET | Faculty | View all submissions |
| `/api/faculty/results` | GET | Faculty | View results summary |

### JWT Token Structure

```
Header.Payload.Signature

Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "id": 1, "username": "student1", "name": "Rahul Sharma", "role": "student", "iat": ..., "exp": ... }
Signature: HMAC-SHA256(base64(header) + "." + base64(payload), secret_key)
```

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLIENT (Browser)                        │
│                                                                  │
│  [Login Form] ──► POST /api/login ──► Store JWT Token            │
│       │                                                          │
│       ▼                                                          │
│  [Dashboard] ──► API Requests with Authorization: Bearer <JWT>   │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                       SERVER (Express.js)                        │
│                                                                  │
│  ┌─────────────────┐    ┌──────────────────┐    ┌──────────────┐│
│  │ Token Extracted  │───►│ JWT Verification │───►│ Role Check   ││
│  │ from Header      │    │ (Signature +     │    │ (student or  ││
│  │                  │    │  Expiry Check)   │    │  faculty)    ││
│  └─────────────────┘    └──────────────────┘    └──────┬───────┘│
│                                                         │        │
│                              ┌───────────────────────────┘        │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Protected Endpoints                      │ │
│  │  Student: View Exams, Submit Answers                        │ │
│  │  Faculty: Create Exams, View Submissions, Manage Results    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Result

### Server Console Output

```
=======================================================
   VITONLINE Secure Examination System
   JWT Authentication with Role-Based Access Control
=======================================================

[SERVER] Running on http://localhost:3000
[SERVER] JWT Secret: a3f7b2c8d1e9f456... (256 bits)
[SERVER] Token Expiry: 1h

[SERVER] Registered Users:
  - faculty1 / faculty123  (faculty) — Dr. Ananya Verma
  - faculty2 / faculty456  (faculty) — Prof. Rajesh Kumar
  - student1 / student123  (student) — Rahul Sharma
  - student2 / student456  (student) — Priya Patel
  - student3 / student789  (student) — Arjun Nair

[SERVER] Waiting for requests...

[LOGIN] SUCCESS - User: Rahul Sharma | Role: student | Token issued
[AUTH] Access GRANTED - User: Rahul Sharma (student) | GET /api/student/exams
[AUTH] Access GRANTED - User: Rahul Sharma (student) | GET /api/student/exams/1
[AUTH] Access GRANTED - User: Rahul Sharma (student) | POST /api/student/submit
[EXAM] Submission by Rahul Sharma for "Cryptography Mid-Term" - Score: 2/3

[LOGIN] SUCCESS - User: Dr. Ananya Verma | Role: faculty | Token issued
[AUTH] Access GRANTED - User: Dr. Ananya Verma (faculty) | GET /api/faculty/exams
[AUTH] Access GRANTED - User: Dr. Ananya Verma (faculty) | GET /api/faculty/submissions
[AUTH] Access GRANTED - User: Dr. Ananya Verma (faculty) | GET /api/faculty/results

--- Access Denied Tests ---
[AUTH] Access DENIED - No token provided | GET /api/test/no-token
[AUTHZ] FORBIDDEN - User: Dr. Ananya Verma (faculty) tried to access /api/student/exams | Required: student
[AUTHZ] FORBIDDEN - User: Dr. Ananya Verma (faculty) tried to access /api/student/submit | Required: student
```

### Access Control Verification

| Test Scenario | Expected | Actual |
|---|---|---|
| Student accesses `/api/student/exams` | ✅ Granted | ✅ Granted |
| Student submits answers | ✅ Granted | ✅ Granted |
| Faculty creates exam | ✅ Granted | ✅ Granted |
| Faculty views submissions | ✅ Granted | ✅ Granted |
| Faculty accesses `/api/student/exams` | 🚫 Denied (403) | 🚫 Denied (403) — INSUFFICIENT_ROLE |
| Student accesses `/api/faculty/exams` | 🚫 Denied (403) | 🚫 Denied (403) — INSUFFICIENT_ROLE |
| Request without token | 🚫 Denied (401) | 🚫 Denied (401) — TOKEN_MISSING |
| Request with expired token | 🚫 Denied (401) | 🚫 Denied (401) — TOKEN_EXPIRED |
| Request after logout | 🚫 Denied (401) | 🚫 Denied (401) — TOKEN_BLACKLISTED |

### Conclusion

The JWT-based authentication and authorization system successfully implements:

| Feature | Mechanism |
|---|---|
| **Authentication** | JWT (HS256) — Signed tokens verify user identity |
| **Authorization** | Role-based middleware — Endpoints restricted by user role |
| **Stateless Sessions** | JWT contains all session info; no server-side session storage |
| **Token Expiry** | Tokens expire after 1 hour; expired tokens are rejected |
| **Token Invalidation** | Logout blacklists the token for immediate revocation |

The execution flow — **Login → JWT Generation (with Role) → Token Usage → Token Verification → Role-Based Authorization → Access Control** — was successfully demonstrated with both Student and Faculty roles.
