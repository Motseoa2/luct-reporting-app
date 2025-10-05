const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'password123',
    database: process.env.DB_NAME || 'luct_reporting_system'
});

// Connect to database
db.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed:', err);
        process.exit(1);
    }
    console.log('✅ Connected to MySQL database');
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'luct-reporting-secret-key';

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Max 10 attempts per window
    message: {
        success: false,
        message: 'Too many login attempts, please try again after 15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiting for quick access
const quickAccessLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 3, // Max 3 quick access attempts per window
    message: {
        success: false,
        message: 'Too many quick access attempts, please use manual login'
    }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access token required',
            code: 'NO_TOKEN'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token',
                code: 'INVALID_TOKEN'
            });
        }
        
        // Add security context to request
        req.user = {
            ...user,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        };
        
        next();
    });
};

// ------------------- HEALTH CHECK -------------------
app.get('/api/health', (req, res) => {
    // Test database connection
    db.query('SELECT 1 as test', (err) => {
        const dbStatus = err ? 'DISCONNECTED' : 'CONNECTED';
        
        res.json({ 
            status: 'OK', 
            message: 'LUCT Reporting System API is running',
            timestamp: new Date().toISOString(),
            database: dbStatus,
            security: {
                rateLimiting: 'Active',
                bcrypt: 'Enabled',
                jwt: 'Active'
            }
        });
    });
});

// ------------------- SECURE AUTHENTICATION WITH BCRYPT -------------------
app.post('/api/auth/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;

    console.log('🔑 Faculty login attempt:', { email, ip: req.ip });

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }

    const sql = 'SELECT id, name, email, role, faculty, password FROM users WHERE email = ?';
    
    db.query(sql, [email], async (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Server error' 
            });
        }
        
        if (results.length === 0) {
            console.log('❌ User not found:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const user = results[0];
        
        try {
            const passwordValid = await bcrypt.compare(password, user.password);
            
            if (passwordValid) {
                console.log('✅ Login successful for:', user.name);
                
                const token = jwt.sign(
                    { 
                        id: user.id, 
                        email: user.email, 
                        role: user.role,
                        name: user.name 
                    },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email,
                        role: user.role,
                        faculty: user.faculty
                    },
                    token: token
                });
            } else {
                console.log('❌ Password mismatch for:', email);
                res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }
        } catch (error) {
            console.error('❌ Password comparison error:', error);
            res.status(500).json({
                success: false,
                message: 'Authentication error'
            });
        }
    });
});

// Student login endpoint with bcrypt
app.post('/api/auth/student-login', loginLimiter, (req, res) => {
    const { studentId, password } = req.body;

    console.log('🎓 Student login attempt:', { studentId, ip: req.ip });

    if (!studentId || !password) {
        return res.status(400).json({
            success: false,
            message: 'Student ID and password are required'
        });
    }

    const sql = 'SELECT id, name, email, student_id, program, semester, password FROM students WHERE student_id = ?';
    
    db.query(sql, [studentId], async (err, results) => {
        if (err) {
            console.error('❌ Student login error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Server error' 
            });
        }
        
        if (results.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid student ID or password'
            });
        }

        const student = results[0];
        
        try {
            const passwordValid = await bcrypt.compare(password, student.password);
            
            if (passwordValid) {
                const token = jwt.sign(
                    { 
                        id: student.id, 
                        studentId: student.student_id, 
                        role: 'student',
                        name: student.name 
                    },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.json({
                    success: true,
                    user: {
                        id: student.id,
                        name: student.name,
                        email: student.email,
                        studentId: student.student_id,
                        program: student.program,
                        semester: student.semester,
                        role: 'student'
                    },
                    token: token
                });
            } else {
                res.status(401).json({
                    success: false,
                    message: 'Invalid student ID or password'
                });
            }
        } catch (error) {
            console.error('❌ Student password comparison error:', error);
            res.status(500).json({
                success: false,
                message: 'Authentication error'
            });
        }
    });
});

// ------------------- FIXED SECURE QUICK ACCESS ENDPOINT -------------------
app.post('/api/auth/secure-quick-access', quickAccessLimiter, (req, res) => {
    const { accessCode, userType } = req.body;
    
    console.log('🔐 Secure quick access attempt:', { accessCode, userType, ip: req.ip });

    // Validate access code format
    if (!accessCode || accessCode.length !== 6) {
        return res.status(400).json({
            success: false,
            message: 'Invalid access code format. Must be 6 characters.'
        });
    }

    // Map access codes to actual student IDs and faculty emails
    const accessMap = {
        'STU001': '901017118',
        'STU002': '901017119', 
        'STU003': '901017120',
        'STU004': '901017121',
        'LECT01': 'ntate.moloi@luct.ac.za',
        'PRL001': 'ntate.mokoena@luct.ac.za',
        'PL001': 'ntate.mohlomi@luct.ac.za'
    };

    const lookupValue = accessMap[accessCode.toUpperCase()];
    
    if (!lookupValue) {
        console.log('❌ Invalid access code:', accessCode);
        return res.status(401).json({
            success: false,
            message: 'Invalid access code'
        });
    }

    console.log('✅ Access code mapped:', accessCode, '->', lookupValue);

    // Determine if it's a student or faculty
    const isStudent = accessCode.toUpperCase().startsWith('STU');
    
    if (isStudent) {
        // Lookup student by student_id
        const sql = 'SELECT id, name, email, student_id, program, semester FROM students WHERE student_id = ?';
        
        db.query(sql, [lookupValue], (err, results) => {
            if (err) {
                console.error('❌ Student lookup error:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Security service unavailable. Please try again.'
                });
            }

            if (results.length === 0) {
                console.log('❌ Student not found with ID:', lookupValue);
                return res.status(401).json({
                    success: false,
                    message: 'Student account not found'
                });
            }

            const student = results[0];
            console.log('✅ Student found for quick access:', student.name);

            // Generate JWT token for student
            const token = jwt.sign(
                { 
                    id: student.id, 
                    studentId: student.student_id, 
                    role: 'student',
                    name: student.name 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Security log
            console.log('🔒 Security Log - Student Access:', {
                accessCode: accessCode,
                studentId: student.student_id,
                ip: req.ip,
                timestamp: new Date().toISOString(),
                success: true
            });

            res.json({
                success: true,
                user: {
                    id: student.id,
                    name: student.name,
                    email: student.email,
                    studentId: student.student_id,
                    program: student.program,
                    semester: student.semester,
                    role: 'student'
                },
                token: token,
                message: 'Secure student access granted'
            });
        });
    } else {
        // Lookup faculty by email
        const sql = 'SELECT id, name, email, role, faculty FROM users WHERE email = ?';
        
        db.query(sql, [lookupValue], (err, results) => {
            if (err) {
                console.error('❌ Faculty lookup error:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Security service unavailable. Please try again.'
                });
            }

            if (results.length === 0) {
                console.log('❌ Faculty not found with email:', lookupValue);
                return res.status(401).json({
                    success: false,
                    message: 'Faculty account not found'
                });
            }

            const user = results[0];
            console.log('✅ Faculty found for quick access:', user.name);

            // Generate JWT token for faculty
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email, 
                    role: user.role,
                    name: user.name 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Security log
            console.log('🔒 Security Log - Faculty Access:', {
                accessCode: accessCode,
                email: user.email,
                role: user.role,
                ip: req.ip,
                timestamp: new Date().toISOString(),
                success: true
            });

            res.json({
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role,
                    faculty: user.faculty
                },
                token: token,
                message: 'Secure faculty access granted'
            });
        });
    }
});

// ------------------- STUDENT REGISTRATION WITH BCRYPT -------------------
app.post('/api/auth/student-register', async (req, res) => {
    const { fullName, studentId, program, email, password, confirmPassword } = req.body;

    console.log('🎓 Student registration attempt:', { 
        fullName, 
        studentId, 
        program, 
        email,
        ip: req.ip
    });

    // Validate required fields
    if (!fullName || !studentId || !program || !email || !password || !confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
        return res.status(400).json({
            success: false,
            message: 'Passwords do not match'
        });
    }

    // Validate password length
    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 6 characters'
        });
    }

    try {
        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if student ID or email already exists
        const checkSql = 'SELECT * FROM students WHERE student_id = ? OR email = ?';
        
        db.query(checkSql, [studentId, email], (err, results) => {
            if (err) {
                console.error('❌ Student registration check error:', err);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Server error during registration check' 
                });
            }

            if (results.length > 0) {
                const existing = results[0];
                if (existing.student_id === studentId) {
                    return res.status(400).json({
                        success: false,
                        message: 'Student ID already exists'
                    });
                }
                if (existing.email === email) {
                    return res.status(400).json({
                        success: false,
                        message: 'Email already exists'
                    });
                }
            }

            // Insert new student with hashed password
            const insertSql = `
                INSERT INTO students (name, email, student_id, password, program, semester, created_at) 
                VALUES (?, ?, ?, ?, ?, 1, NOW())
            `;
            
            db.query(insertSql, [fullName, email, studentId, hashedPassword, program], (err, result) => {
                if (err) {
                    console.error('❌ Student registration insert error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Failed to create student account' 
                    });
                }

                console.log('✅ Student registered successfully:', {
                    id: result.insertId,
                    name: fullName,
                    studentId: studentId
                });

                // Generate JWT token for immediate login
                const token = jwt.sign(
                    { 
                        id: result.insertId, 
                        studentId: studentId, 
                        role: 'student',
                        name: fullName 
                    },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                // Return success response with user data
                res.status(201).json({
                    success: true,
                    message: 'Student account created successfully!',
                    user: {
                        id: result.insertId,
                        name: fullName,
                        email: email,
                        studentId: studentId,
                        program: program,
                        semester: 1,
                        role: 'student'
                    },
                    token: token
                });
            });
        });
    } catch (error) {
        console.error('❌ Password hashing error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
});

// ------------------- SECURITY MONITORING ENDPOINT -------------------
app.get('/api/security/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'pl' && req.user.role !== 'prl') {
        return res.status(403).json({ 
            success: false,
            error: 'Access denied. PL or PRL role required.' 
        });
    }

    res.json({
        security: {
            bcryptEnabled: true,
            rateLimiting: true,
            jwtExpiry: '24h',
            quickAccessLimit: '3 attempts per 5 minutes',
            loginLimit: '10 attempts per 15 minutes',
            timestamp: new Date().toISOString()
        },
        system: {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            environment: process.env.NODE_ENV || 'development'
        }
    });
});

// ------------------- COURSES -------------------
app.get('/api/courses', authenticateToken, (req, res) => {
    const { search, program } = req.query;
    
    let sql = `
        SELECT c.*, u.name as lecturer_name 
        FROM courses c 
        LEFT JOIN users u ON c.assigned_lecturer_id = u.id 
        WHERE 1=1
    `;
    let params = [];

    if (search) {
        sql += ' AND (c.course_name LIKE ? OR c.course_code LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    if (program) {
        sql += ' AND c.program = ?';
        params.push(program);
    }

    // Role-based filtering
    if (req.user.role === 'lecturer') {
        sql += ' AND c.assigned_lecturer_id = ?';
        params.push(req.user.id);
    }

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error('❌ Courses error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});

// Add new course (PL only)
app.post('/api/courses', authenticateToken, (req, res) => {
    if (req.user.role !== 'pl') {
        return res.status(403).json({ error: 'Access denied. PL role required.' });
    }

    const { course_code, course_name, program, semester, total_students, assigned_lecturer_id } = req.body;

    const sql = `
        INSERT INTO courses (course_code, course_name, program, semester, total_students, assigned_lecturer_id)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(sql, [course_code, course_name, program, semester, total_students, assigned_lecturer_id], (err, result) => {
        if (err) {
            console.error('❌ Course insert error:', err);
            return res.status(500).json({ error: 'Failed to add course' });
        }
        
        res.json({ 
            success: true, 
            message: 'Course added successfully',
            courseId: result.insertId
        });
    });
});

// ------------------- REPORTS -------------------

// Get reports with search and filtering
app.get('/api/reports', authenticateToken, (req, res) => {
    const { search, status, course, lecturer } = req.query;
    
    let sql = `
        SELECT r.*, 
               u.name as lecturer_name, 
               c.course_name, 
               c.course_code,
               cl.class_name
        FROM reports r
        LEFT JOIN users u ON r.lecturer_id = u.id
        LEFT JOIN courses c ON r.course_id = c.id
        LEFT JOIN classes cl ON r.class_id = cl.id
        WHERE 1=1
    `;
    let params = [];

    // Role-based access control
    if (req.user.role === 'lecturer') {
        sql += ' AND r.lecturer_id = ?';
        params.push(req.user.id);
    } else if (req.user.role === 'prl') {
        sql += ' AND r.status IN ("submitted", "prl_reviewed")';
    } else if (req.user.role === 'pl') {
        sql += ' AND r.status = "prl_reviewed"';
    }

    if (search) {
        sql += ` AND (c.course_name LIKE ? OR u.name LIKE ? OR r.topic_taught LIKE ? OR cl.class_name LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (status && status !== 'all') {
        sql += ' AND r.status = ?';
        params.push(status);
    }

    if (course && course !== 'all') {
        sql += ' AND r.course_id = ?';
        params.push(course);
    }

    if (lecturer) {
        sql += ' AND r.lecturer_id = ?';
        params.push(lecturer);
    }

    sql += ' ORDER BY r.created_at DESC';

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error('❌ Reports fetch error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});

// Submit new report (Lecturer) - FIXED VERSION
app.post('/api/reports', authenticateToken, (req, res) => {
    if (req.user.role !== 'lecturer') {
        return res.status(403).json({ error: 'Access denied. Lecturer role required.' });
    }

    const {
        faculty_name, class_name, week_of_reporting, date_of_lecture,
        course_id, actual_students_present, venue, scheduled_time,
        topic_taught, learning_outcomes, recommendations
    } = req.body;

    console.log('📝 Report submission data:', {
        class_name, course_id, faculty_name, lecturer: req.user.name
    });

    // Get class_id from class_name
    const findClassSql = 'SELECT id FROM classes WHERE class_name = ? LIMIT 1';
    
    db.query(findClassSql, [class_name], (err, classResults) => {
        if (err) {
            console.error('❌ Class lookup error:', err);
            return res.status(500).json({ error: 'Server error during class lookup' });
        }

        if (classResults.length === 0) {
            console.error('❌ Class not found:', class_name);
            return res.status(400).json({ error: `Class "${class_name}" not found in database` });
        }

        const class_id = classResults[0].id;
        console.log('✅ Found class ID:', class_id);

        // Get total students from course
        const courseSql = 'SELECT total_registered_students FROM courses WHERE id = ?';
        db.query(courseSql, [course_id], (err, courseResults) => {
            if (err) {
                console.error('❌ Course lookup error:', err);
                return res.status(500).json({ error: 'Server error during course lookup' });
            }

            if (courseResults.length === 0) {
                return res.status(400).json({ error: 'Course not found' });
            }

            const total_registered_students = courseResults[0]?.total_registered_students || 0;
            console.log('✅ Course found, total students:', total_registered_students);

            const insertSql = `
                INSERT INTO reports 
                (faculty_name, class_id, week_of_reporting, date_of_lecture, course_id,
                 lecturer_id, actual_students_present, total_registered_students,
                 venue, scheduled_time, topic_taught, learning_outcomes, recommendations, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted')
            `;
            
            db.query(insertSql, [
                faculty_name, class_id, week_of_reporting, date_of_lecture, course_id,
                req.user.id, actual_students_present, total_registered_students,
                venue, scheduled_time, topic_taught, learning_outcomes, recommendations
            ], (err, result) => {
                if (err) {
                    console.error('❌ Report insert error:', err);
                    return res.status(500).json({ error: 'Failed to submit report: ' + err.message });
                }
                
                console.log('✅ Report submitted successfully, ID:', result.insertId);
                res.json({ 
                    success: true, 
                    message: 'Report submitted successfully',
                    reportId: result.insertId
                });
            });
        });
    });
});

// PRL Feedback endpoint
app.post('/api/reports/:id/feedback', authenticateToken, (req, res) => {
    if (req.user.role !== 'prl') {
        return res.status(403).json({ error: 'Access denied. PRL role required.' });
    }

    const reportId = req.params.id;
    const { feedback } = req.body;

    const sql = 'UPDATE reports SET prl_feedback = ?, status = "prl_reviewed" WHERE id = ?';
    
    db.query(sql, [feedback, reportId], (err, result) => {
        if (err) {
            console.error('❌ Feedback update error:', err);
            return res.status(500).json({ error: 'Failed to submit feedback' });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Report not found' });
        }
        
        res.json({ 
            success: true, 
            message: 'Feedback submitted successfully'
        });
    });
});

// ------------------- RATINGS -------------------

// Submit rating (All roles can rate)
app.post('/api/ratings', authenticateToken, (req, res) => {
    const { report_id, rating, comments } = req.body;

    // Validate rating
    if (rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    const sql = 'INSERT INTO ratings (report_id, rated_by, rating, comments) VALUES (?, ?, ?, ?)';
    
    db.query(sql, [report_id, req.user.id, rating, comments], (err, result) => {
        if (err) {
            console.error('❌ Rating insert error:', err);
            return res.status(500).json({ error: 'Failed to submit rating' });
        }
        
        res.json({ 
            success: true, 
            message: 'Rating submitted successfully',
            ratingId: result.insertId
        });
    });
});

// Get ratings
app.get('/api/ratings', authenticateToken, (req, res) => {
    const sql = `
        SELECT r.*, u.name as rater_name, rep.course_name 
        FROM ratings r
        LEFT JOIN users u ON r.rated_by = u.id
        LEFT JOIN reports rep ON r.report_id = rep.id
        ORDER BY r.created_at DESC
    `;
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error('❌ Ratings fetch error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});

// ------------------- EXCEL EXPORT -------------------

app.get('/api/reports/export', authenticateToken, async (req, res) => {
    try {
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('LUCT Reports');

        // Add headers
        worksheet.columns = [
            { header: 'Faculty', key: 'faculty_name', width: 20 },
            { header: 'Class', key: 'class_name', width: 15 },
            { header: 'Course Code', key: 'course_code', width: 15 },
            { header: 'Course Name', key: 'course_name', width: 25 },
            { header: 'Lecturer', key: 'lecturer_name', width: 20 },
            { header: 'Week', key: 'week_of_reporting', width: 12 },
            { header: 'Lecture Date', key: 'date_of_lecture', width: 12 },
            { header: 'Students Present', key: 'actual_students_present', width: 15 },
            { header: 'Total Students', key: 'total_registered_students', width: 15 },
            { header: 'Attendance %', key: 'attendance_rate', width: 12 },
            { header: 'Venue', key: 'venue', width: 15 },
            { header: 'Scheduled Time', key: 'scheduled_time', width: 15 },
            { header: 'Topic', key: 'topic_taught', width: 30 },
            { header: 'Status', key: 'status', width: 12 },
            { header: 'PRL Feedback', key: 'prl_feedback', width: 30 }
        ];

        // Get reports data with role-based filtering
        let sql = `
            SELECT r.*, 
                   u.name as lecturer_name, 
                   c.course_name, 
                   c.course_code, 
                   cl.class_name,
                   ROUND((r.actual_students_present / r.total_registered_students) * 100, 2) as attendance_rate
            FROM reports r
            LEFT JOIN users u ON r.lecturer_id = u.id
            LEFT JOIN courses c ON r.course_id = c.id
            LEFT JOIN classes cl ON r.class_id = cl.id
        `;
        let params = [];

        // Role-based filtering for export too
        if (req.user.role === 'lecturer') {
            sql += ' WHERE r.lecturer_id = ?';
            params.push(req.user.id);
        } else if (req.user.role === 'prl') {
            sql += ' WHERE r.status IN ("submitted", "prl_reviewed")';
        } else if (req.user.role === 'pl') {
            sql += ' WHERE r.status = "prl_reviewed"';
        }

        sql += ' ORDER BY r.created_at DESC';

        db.query(sql, params, async (err, results) => {
            if (err) {
                console.error('❌ Export data error:', err);
                return res.status(500).json({ error: 'Failed to generate export' });
            }

            // Add data rows
            worksheet.addRows(results);

            // Style headers
            worksheet.getRow(1).font = { bold: true };
            worksheet.getRow(1).fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FFE6E6FA' }
            };

            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            res.setHeader('Content-Disposition', `attachment; filename=luct-reports-${new Date().toISOString().split('T')[0]}.xlsx`);

            await workbook.xlsx.write(res);
            res.end();
        });

    } catch (error) {
        console.error('❌ Excel export error:', error);
        res.status(500).json({ error: 'Failed to generate Excel file' });
    }
});

// ------------------- USERS -------------------

app.get('/api/users', authenticateToken, (req, res) => {
    const { role } = req.query;
    
    let sql = 'SELECT id, name, email, role, faculty FROM users WHERE 1=1';
    let params = [];

    if (role) {
        sql += ' AND role = ?';
        params.push(role);
    }

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error('❌ Users fetch error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});
// ------------------- STUDENT ENROLLMENTS -------------------
app.get('/api/student/courses', authenticateToken, (req, res) => {
    if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Access denied. Student role required.' });
    }

    const sql = `
        SELECT c.*, u.name as lecturer_name 
        FROM courses c
        LEFT JOIN enrollments e ON c.id = e.course_id
        LEFT JOIN users u ON c.assigned_lecturer_id = u.id
        WHERE e.student_id = ?
        ORDER BY c.semester, c.course_code
    `;
    
    db.query(sql, [req.user.id], (err, results) => {
        if (err) {
            console.error('❌ Student courses error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});

// Get student reports (reports for courses they're enrolled in)
app.get('/api/student/reports', authenticateToken, (req, res) => {
    if (req.user.role !== 'student') {
        return res.status(403).json({ error: 'Access denied. Student role required.' });
    }

    const sql = `
        SELECT r.*, c.course_name, c.course_code, u.name as lecturer_name, cl.class_name
        FROM reports r
        JOIN courses c ON r.course_id = c.id
        JOIN enrollments e ON c.id = e.course_id
        LEFT JOIN users u ON r.lecturer_id = u.id
        LEFT JOIN classes cl ON r.class_id = cl.id
        WHERE e.student_id = ?
        ORDER BY r.date_of_lecture DESC
    `;
    
    db.query(sql, [req.user.id], (err, results) => {
        if (err) {
            console.error('❌ Student reports error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(results);
    });
});

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 LUCT Reporting System API Ready`);
    console.log(`🔐 Enhanced Security: ACTIVE`);
    console.log(`🛡️  Rate Limiting: ENABLED`);
    console.log(`🔑 Quick Access: SECURE MODE`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔑 Login endpoint: http://localhost:${PORT}/api/auth/login`);
    console.log(`🔐 Secure quick access: http://localhost:${PORT}/api/auth/secure-quick-access`);
    console.log(`🎓 Student login: http://localhost:${PORT}/api/auth/student-login`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('🔄 Shutting down server gracefully...');
    db.end();
    process.exit(0);
});