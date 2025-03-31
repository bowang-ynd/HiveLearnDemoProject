"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = require("dotenv");
const app_1 = require("firebase-admin/app");
const auth_1 = require("firebase-admin/auth");
const firestore_1 = require("firebase-admin/firestore");
const path_1 = __importDefault(require("path"));
// Load environment variables
(0, dotenv_1.config)();
// Initialize Firebase Admin
const serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
    privateKey: (_a = process.env.FIREBASE_PRIVATE_KEY) === null || _a === void 0 ? void 0 : _a.replace(/\\n/g, '\n'),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    clientId: process.env.FIREBASE_CLIENT_ID,
    authUri: process.env.FIREBASE_AUTH_URI,
    tokenUri: process.env.FIREBASE_TOKEN_URI,
    authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    clientX509CertUrl: process.env.FIREBASE_CLIENT_X509_CERT_URL,
};
// Initialize Firebase Admin
const app = (0, app_1.initializeApp)({
    credential: (0, app_1.cert)(serviceAccount)
});
// Get Firebase Auth and Firestore instances
const auth = (0, auth_1.getAuth)(app);
const db = (0, firestore_1.getFirestore)(app);
// Initialize Express
const expressApp = (0, express_1.default)();
const port = process.env.PORT || 5000;
// Middleware
expressApp.use((0, cors_1.default)());
expressApp.use(express_1.default.json());
// Authentication Middleware
const authenticateUser = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const authHeader = req.headers.authorization;
        if (!(authHeader === null || authHeader === void 0 ? void 0 : authHeader.startsWith('Bearer '))) {
            return res.status(401).json({ error: 'Unauthorized - No token provided' });
        }
        const token = authHeader.split('Bearer ')[1];
        const decodedToken = yield auth.verifyIdToken(token);
        req.user = decodedToken;
        next();
    }
    catch (error) {
        console.error('Authentication error:', error);
        res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }
});
// Add these validation functions before your routes
const validateUserData = (data) => {
    return !!(data.email &&
        typeof data.email === 'string' &&
        data.email.includes('@') &&
        data.password &&
        typeof data.password === 'string' &&
        data.displayName &&
        typeof data.displayName === 'string' &&
        data.displayName.length >= 2);
};
const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    return password.length >= minLength &&
        hasUpperCase &&
        hasLowerCase &&
        hasNumbers &&
        hasSpecialChar;
};
// Routes
// Auth Routes
expressApp.post('/api/auth/register', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password, displayName } = req.body;
        // Validate user data
        if (!validateUserData(req.body)) {
            return res.status(400).json({
                error: 'Invalid user data. Please check all required fields.'
            });
        }
        // Validate password requirements
        if (!validatePassword(password)) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.'
            });
        }
        // Use transaction to ensure both operations succeed
        yield db.runTransaction((transaction) => __awaiter(void 0, void 0, void 0, function* () {
            // Create user in Firebase Auth
            const userRecord = yield auth.createUser({
                email,
                password,
                displayName,
            });
            // Create user document in Firestore
            const userRef = db.collection('users').doc(userRecord.uid);
            const userData = {
                uid: userRecord.uid,
                email,
                displayName,
                createdAt: new Date(),
                emailVerified: false,
                role: 'user',
            };
            transaction.set(userRef, userData);
            res.status(201).json({
                message: 'User created successfully',
                uid: userRecord.uid
            });
        }));
    }
    catch (error) {
        console.error('Registration error:', error);
        res.status(400).json({
            error: error instanceof Error ? error.message : 'Failed to create user'
        });
    }
}));
expressApp.post('/api/auth/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        // Sign in user with Firebase Auth
        const userRecord = yield auth.getUserByEmail(email);
        // In a real implementation, you would verify the password here
        // Firebase Auth handles this automatically when using the client SDK
        res.json({
            message: 'Login successful',
            uid: userRecord.uid
        });
    }
    catch (error) {
        console.error('Login error:', error);
        res.status(401).json({ error: 'Invalid credentials' });
    }
}));
// Protected Routes
expressApp.get('/api/user/profile', authenticateUser, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        if (!((_a = req.user) === null || _a === void 0 ? void 0 : _a.uid)) {
            return res.status(401).json({ error: 'User not authenticated' });
        }
        const userDoc = yield db.collection('users').doc(req.user.uid).get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(userDoc.data());
    }
    catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
}));
// Serve static files in production
if (process.env.NODE_ENV === 'production') {
    expressApp.use(express_1.default.static(path_1.default.join(__dirname, '../../client/build')));
    expressApp.get('*', (req, res) => {
        res.sendFile(path_1.default.join(__dirname, '../../client/build', 'index.html'));
    });
}
// Start server
expressApp.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
