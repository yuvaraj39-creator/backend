const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const nodemailer = require('nodemailer');

// Import models
const User = require('./models/user');
const Course = require('./models/Course');
const Poster = require('./models/Poster');
const AdminLogin = require('./models/adminlogin');
const OTP = require('./models/OTP');
const Application = require('./models/Application');
const Community = require('./models/Community');
const QuizRedeem = require('./models/QuizRedeem');

const app = express();

// CORS configuration
const corsOptions = {
    origin: [
        "https://u1technology.netlify.app",
        "https://u1technology.co.in",
        "https://www.u1technology.co.in",
        "http://localhost:3000",
        "http://127.0.0.1:5500"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Apply CORS BEFORE helmet
app.use(cors(corsOptions));

app.use(helmet({
  crossOriginResourcePolicy: false
}));



// Body parsing middleware with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// NoSQL injection protection
app.use(mongoSanitize());

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
// OTP Limiter 
const otpLimiter = rateLimit({
    windowMs: 150 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 3 OTP requests per windowMs
    message: {
        success: false,
        message: 'Too many OTP requests, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting to specific routes
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/send-otp', otpLimiter);
app.use('/api/auth/verify-otp', otpLimiter);

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Validate required environment variables
if (!process.env.JWT_SECRET) {
    console.error('❌ JWT_SECRET environment variable is required');
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI environment variable is required');
    process.exit(1);
}

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log('✅ Connected to MongoDB');
        return AdminLogin.createDefaultAdmin();
    })
    .then(() => {
        console.log('✅ Default admin setup completed');
    })
    .catch((error) => {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    });

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        req.user = user;
        next();
    });
};

// Admin authentication middleware
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Verify the user is an admin
        const admin = await AdminLogin.findById(decoded.adminId);
        if (!admin || admin.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Admin access required'
            });
        }

        req.admin = admin;
        req.user = {
            userId: admin._id,
            email: admin.email,
            role: admin.role
        };
        next();
    } catch (error) {
        console.error('Admin token verification error:', error);
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
};

// Routes
app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Backend is running successfully!"
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});


// Contact form submission
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;

        // Validate required fields
        if (!name || !email || !subject || !message) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Check if email credentials are configured
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.warn('Email credentials not configured. Contact form submission received:', { name, email, subject });
            return res.status(500).json({
                success: false,
                message: 'Email service not configured. Please contact administrator.'
            });
        }

        // Setup email transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        // Email content for admin
        const adminMailOptions = {
            from: `"U1 Technology Website" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: `New Contact Form Submission: ${subject}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #fff; border: 1px solid rgba(128, 0, 32, 0.3); border-radius: 10px; padding: 20px; box-shadow: 0 0 10px rgba(128, 0, 32, 0.2);">
                    <h2 style="color: rgba(128, 0, 32, 0.7); text-align: center;">New Contact Form Submission</h2>
                    <div style="background-color: rgba(128, 0, 32, 0.1); padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <p><strong>Name:</strong> ${name}</p>
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Subject:</strong> ${subject}</p>
                        <p><strong>Message:</strong></p>
                        <div style="background-color: white; padding: 10px; border-radius: 5px; border: 1px solid rgba(128, 0, 32, 0.2);">
                            ${message.replace(/\n/g, '<br>')}
                        </div>
                    </div>
                    <p style="color: #555; font-size: 14px;">
                        This message was sent from the U1 Technology Institute website contact form.
                    </p>
                </div>
            `
        };

        // Email content for user (confirmation)
        const userMailOptions = {
            from: `"U1 Technology Institute" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Thank you for contacting U1 Technology Institute',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #fff; border: 1px solid rgba(128, 0, 32, 0.3); border-radius: 10px; padding: 20px; box-shadow: 0 0 10px rgba(128, 0, 32, 0.2);">
                    <h2 style="color: rgba(128, 0, 32, 0.7); text-align: center;">Thank You for Contacting Us</h2>
                    <p style="font-size: 16px; color: #333;">
                        Dear ${name},
                    </p>
                    <p style="font-size: 16px; color: #333;">
                        Thank you for reaching out to U1 Technology Institute. We have received your message and will get back to you within 24-48 hours.
                    </p>
                    <div style="background-color: rgba(128, 0, 32, 0.1); padding: 15px; border-radius: 8px; margin: 20px 0;">
                        <p><strong>Your Message:</strong></p>
                        <div style="background-color: white; padding: 10px; border-radius: 5px; border: 1px solid rgba(128, 0, 32, 0.2);">
                            ${message.replace(/\n/g, '<br>')}
                        </div>
                    </div>
                    <p style="color: #555; font-size: 14px;">
                        If you have any urgent inquiries, please call us at +91 99523 91994.
                    </p>
                    <hr style="border: none; border-top: 1px solid rgba(128, 0, 32, 0.2); margin: 25px 0;">
                    <p style="color: #777; font-size: 12px; text-align: center;">
                        This is an automated response. Please do not reply to this email.
                    </p>
                    <p style="text-align: center; color: rgba(128, 0, 32, 0.7); font-size: 12px; margin-top: 20px;">
                        — U1 Technology Institute Team
                    </p>
                </div>
            `
        };

        // Send emails
        await transporter.sendMail(adminMailOptions);
        await transporter.sendMail(userMailOptions);

        console.log(`Contact form submission received and emails sent for: ${email}`);

        res.json({
            success: true,
            message: 'Message sent successfully'
        });

    } catch (error) {
        console.error('Contact form error:', error);

        // More specific error messages
        if (error.code === 'EAUTH') {
            return res.status(500).json({
                success: false,
                message: 'Email authentication failed. Please check email configuration.'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to send message. Please try again later.'
        });
    }
});


// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('Admin login attempt:', { email });

        // Find admin by email
        const admin = await AdminLogin.findByEmail(email);

        if (!admin) {
            console.log('Admin not found for email:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check password
        const isPasswordValid = await admin.comparePassword(password);

        if (!isPasswordValid) {
            console.log('Invalid password for admin:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                adminId: admin._id,
                email: admin.email,
                role: admin.role
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Update last login
        await admin.updateLastLogin();

        console.log('Admin login successful:', email);

        res.json({
            success: true,
            message: 'Admin login successful',
            data: {
                user: admin.getProfile(),
                token
            }
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get current admin profile
app.get('/api/admin/me', authenticateAdmin, async (req, res) => {
    try {
        res.json({
            success: true,
            data: {
                user: req.admin.getProfile()
            }
        });
    } catch (error) {
        console.error('Get admin profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Change admin password
app.put('/api/admin/change-password', authenticateAdmin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const admin = req.admin;

        // If currentPassword is provided, verify it
        if (currentPassword) {
            const isCurrentPasswordValid = await admin.comparePassword(currentPassword);
            if (!isCurrentPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Current password is incorrect'
                });
            }
        }

        // Update password
        admin.password = newPassword;
        await admin.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change admin password error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update admin profile
app.put('/api/admin/profile', authenticateAdmin, async (req, res) => {
    try {
        const { name, email } = req.body;

        const admin = req.admin;

        // Update fields if provided
        if (name) admin.name = name.trim();
        if (email) admin.email = email.toLowerCase().trim();

        await admin.save();

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: {
                admin: admin.getProfile()
            }
        });

    } catch (error) {
        console.error('Update admin profile error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Email already exists'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get all admins (super admin only)
app.get('/api/admin/admins', authenticateAdmin, async (req, res) => {
    try {
        const admins = await AdminLogin.find({}, { password: 0 })
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            data: {
                admins,
                total: admins.length
            }
        });

    } catch (error) {
        console.error('Get admins error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Generate and Send OTP
app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
    try {
        const { email, purpose = 'password_reset' } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Check if user exists (for password reset)
        if (purpose === 'password_reset') {
            const user = await User.findOne({
                email: email.toLowerCase().trim()
            });
            if (!user) {
                // Don't reveal whether email exists or not for security
                return res.json({
                    success: true,
                    message: 'If the email exists, an OTP has been sent'
                });
            }
        }

        // Delete any existing OTPs for this email and purpose
        await OTP.deleteOTP(email, purpose);

        // Create new OTP
        const otpDoc = await OTP.createOTP(email, purpose);

        console.log(`OTP generated for ${email}: ${otpDoc.otp}`);

        // Check if email credentials are configured
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.warn('Email credentials not configured. OTP:', otpDoc.otp);
            return res.status(500).json({
                success: false,
                message: 'Email service not configured. Please contact administrator.'
            });
        }

        // Setup email transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD // Note: Fixed variable name
            }
        });

        // Email content
        const mailOptions = {
            from: `"U1 Technology" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your OTP Code',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #fff; border: 1px solid rgba(128, 0, 32, 0.3); border-radius: 10px; padding: 20px; box-shadow: 0 0 10px rgba(128, 0, 32, 0.2);">
            <h2 style="color: rgba(128, 0, 32, 0.7); text-align: center;">Your One-Time Password (OTP)</h2>
            <p style="font-size: 16px; color: #333; text-align: center;">
                Use the following OTP to complete your action:
            </p>
            <div style="background-color: rgba(128, 0, 32, 0.1); color: rgba(128, 0, 32, 0.9); padding: 15px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 5px; margin: 20px auto; border-radius: 8px; border: 1px solid rgba(128, 0, 32, 0.3); width: fit-content;">
                ${otpDoc.otp}
            </div>
            <p style="color: #555; font-size: 14px; text-align: center;">
                This OTP will expire in <strong style="color: rgba(128, 0, 32, 0.7);">10 minutes</strong>. Please do not share this code with anyone.
            </p>
            <hr style="border: none; border-top: 1px solid rgba(128, 0, 32, 0.2); margin: 25px 0;">
            <p style="color: #777; font-size: 12px; text-align: center;">
                If you didn't request this OTP, please ignore this email.
            </p>
            <p style="text-align: center; color: rgba(128, 0, 32, 0.7); font-size: 12px; margin-top: 20px;">
                — U1 Technology Team
            </p>
        </div>
    `
        };


        // Send email
        await transporter.sendMail(mailOptions);
        console.log(`OTP email sent successfully to ${email}`);

        res.json({
            success: true,
            message: 'OTP sent successfully to your email'
        });

    } catch (error) {
        console.error('Send OTP error:', error);

        // More specific error messages
        if (error.code === 'EAUTH') {
            return res.status(500).json({
                success: false,
                message: 'Email authentication failed. Please check email configuration.'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to send OTP. Please try again later.'
        });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp, purpose = 'password_reset' } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Verify OTP using the model
        const verificationResult = await OTP.verifyOTP(email, otp, purpose);

        if (!verificationResult.success) {
            return res.status(400).json({
                success: false,
                message: verificationResult.message
            });
        }

        res.json({
            success: true,
            message: 'OTP verified successfully'
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify OTP'
        });
    }
});

// Reset Password with OTP
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Email, OTP, and new password are required'
            });
        }

        // Verify OTP first
        const verificationResult = await OTP.verifyOTP(email, otp, 'password_reset');

        if (!verificationResult.success) {
            return res.status(400).json({
                success: false,
                message: verificationResult.message
            });
        }

        // Find user using regular mongoose method
        const user = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        // Delete the used OTP
        await OTP.deleteOTP(email, 'password_reset');

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    }
});

// Get OTP status (admin only - for debugging)
app.get('/api/auth/otp-status/:email', authenticateAdmin, async (req, res) => {
    try {
        const { email } = req.params;
        const otpDoc = await OTP.getValidOTP(email);

        if (!otpDoc) {
            return res.json({
                success: false,
                message: 'No active OTP found'
            });
        }

        res.json({
            success: true,
            data: {
                email: otpDoc.email,
                purpose: otpDoc.purpose,
                expiresAt: otpDoc.expiresAt,
                attempts: otpDoc.attempts,
                verified: otpDoc.verified,
                timeRemaining: Math.max(0, Math.floor((otpDoc.expiresAt - new Date()) / 1000 / 60))
            }
        });

    } catch (error) {
        console.error('OTP status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get OTP status'
        });
    }
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const {
            name,
            email,
            phone,
            password,
            experience,
            additionalInfo
        } = req.body;

        console.log('Registration attempt:', {
            name: name?.substring(0, 20) + '...',
            email,
            phone,
            experience
        });

        // Basic validation
        if (!name || !email || !phone || !password || !experience) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required: name, email, phone, password, experience'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email: email.toLowerCase().trim() },
                { phone: phone.trim() }
            ]
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or phone already exists'
            });
        }

        // Create new user
        const user = new User({
            name: name.trim(),
            email: email.toLowerCase().trim(),
            phone: phone.trim(),
            password: password,
            experience: experience,
            additionalInfo: additionalInfo ? additionalInfo.trim() : ''
        });

        // Save user (password will be hashed by pre-save middleware)
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Update last login
        await user.updateLastLogin();

        console.log('User registered successfully:', user.email);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            data: {
                user: user.getProfile(),
                token
            }
        });

    } catch (error) {
        console.error('Registration error details:', error);

        // Mongoose validation error
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => ({
                field: err.path,
                message: err.message
            }));

            console.log('Validation errors:', errors);

            return res.status(400).json({
                success: false,
                message: 'Registration validation failed',
                errors: errors
            });
        }

        // Duplicate key error
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(400).json({
                success: false,
                message: `User with this ${field} already exists`
            });
        }

        console.error('Unexpected registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during registration'
        });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('Login attempt for email:', email);

        // Find user by email using regular mongoose method
        const user = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (!user) {
            console.log('User not found for email:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);

        if (!isPasswordValid) {
            console.log('Invalid password for user:', email);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Update last login
        await user.updateLastLogin();

        console.log('Login successful for user:', email);

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: user.getProfile(),
                token
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get current user profile
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            data: {
                user: user.getProfile()
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone, experience, additionalInfo } = req.body;

        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Update fields if provided
        if (name) user.name = name.trim();
        if (phone) user.phone = phone;
        if (experience) user.experience = experience;
        if (additionalInfo !== undefined) user.additionalInfo = additionalInfo.trim();

        await user.save();

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: {
                user: user.getProfile()
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Change password
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await user.comparePassword(currentPassword);

        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change password error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Forgot password (initiate)
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findByEmail(email);

        if (!user) {
            // Don't reveal whether email exists or not
            return res.json({
                success: true,
                message: 'If the email exists, a password reset link has been sent'
            });
        }

        // In a real application, you would:
        // 1. Generate a reset token
        // 2. Save it to the user document with expiry
        // 3. Send email with reset link

        // For now, we'll just return success
        res.json({
            success: true,
            message: 'If the email exists, a password reset link has been sent'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Logout (client-side token removal)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    // Since we're using JWT, logout is handled client-side by removing the token
    res.json({
        success: true,
        message: 'Logout successful'
    });
});

// Admin routes (protected)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const users = await User.find({}, { password: 0, resetPasswordToken: 0, resetPasswordExpire: 0 })
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            data: {
                users,
                total: users.length
            }
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create new course
app.post('/api/courses', authenticateAdmin, async (req, res) => {
    try {
        const {
            title,
            description,
            miniDescription,
            category,
            seller,
            images,
            offlinePrice,
            offlineOriginalPrice,
            onlinePrice,
            onlineOriginalPrice,
            toolsLanguage,
            learn,
            curriculum,
            status = 'draft'
        } = req.body;

        // Validate required fields
        if (!title || !description || !images || !offlinePrice || !onlinePrice || !category) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        // Validate images array
        if (!Array.isArray(images) || images.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one image is required'
            });
        }

        // Validate learn array
        if (!Array.isArray(learn) || learn.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one learning point is required'
            });
        }

        // Validate curriculum
        if (!Array.isArray(curriculum) || curriculum.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Curriculum is required'
            });
        }

        // Create new course
        const course = new Course({
            title: title.trim(),
            description: description.trim(),
            miniDescription: miniDescription ? miniDescription.trim() : '',
            category: category.trim(),
            seller: seller ? seller.trim() : null,
            images,
            offlinePrice: parseFloat(offlinePrice),
            offlineOriginalPrice: offlineOriginalPrice ? parseFloat(offlineOriginalPrice) : undefined,
            onlinePrice: parseFloat(onlinePrice),
            onlineOriginalPrice: onlineOriginalPrice ? parseFloat(onlineOriginalPrice) : undefined,
            toolsLanguage: toolsLanguage ? toolsLanguage.map(tool => tool.trim()) : [],
            learn: learn.map(point => point.trim()),
            curriculum: curriculum.map(section => ({
                section: section.section.trim(),
                lectures: section.lectures.map(lecture => lecture.trim())
            })),
            status,
            createdBy: req.user.userId || req.user.adminId
        });

        await course.save();

        // Populate createdBy field
        await course.populate('createdBy', 'name email');

        res.status(201).json({
            success: true,
            message: 'Course created successfully',
            data: {
                course
            }
        });

    } catch (error) {
        console.error('Create course error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get all courses (with pagination, search, and filtering)
app.get('/api/courses', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            status = '',
            category = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        // Build query
        let query = { isDeleted: false };

        // Search functionality (updated to include category and seller)
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { 'learn': { $regex: search, $options: 'i' } },
                { 'category': { $regex: search, $options: 'i' } },
                { 'seller': { $regex: search, $options: 'i' } }
            ];
        }

        // Status filter
        if (status) {
            query.status = status;
        }

        // Category filter
        if (category) {
            query.category = { $regex: category, $options: 'i' };
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Get courses with pagination
        const courses = await Course.find(query)
            .populate('createdBy', 'name email')
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum);

        // Get total count for pagination
        const total = await Course.countDocuments(query);
        const totalPages = Math.ceil(total / limitNum);

        res.json({
            success: true,
            data: {
                courses,
                pagination: {
                    currentPage: pageNum,
                    totalPages,
                    totalCourses: total,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1
                }
            }
        });

    } catch (error) {
        console.error('Get courses error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get all course categories
app.get('/api/courses/categories', async (req, res) => {
    try {
        const categories = await Course.distinct('category', { isDeleted: false });

        res.json({
            success: true,
            data: {
                categories: categories.filter(cat => cat).sort()
            }
        });
    } catch (error) {
        console.error('Get categories error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get single course by ID
app.get('/api/courses/:id', async (req, res) => {
    try {
        const course = await Course.findOne({
            _id: req.params.id,
            isDeleted: false
        }).populate('createdBy', 'name email');

        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }

        res.json({
            success: true,
            data: {
                course
            }
        });

    } catch (error) {
        console.error('Get course error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid course ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update course
app.put('/api/courses/:id', authenticateAdmin, async (req, res) => {
    try {
        const {
            title,
            description,
            miniDescription,
            category,
            seller,
            images,
            offlinePrice,
            offlineOriginalPrice,
            onlinePrice,
            onlineOriginalPrice,
            toolsLanguage,
            learn,
            curriculum,
            status,
            students
        } = req.body;

        const course = await Course.findOne({
            _id: req.params.id,
            isDeleted: false
        });

        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }

        // Update fields if provided
        if (title) course.title = title.trim();
        if (description) course.description = description.trim();
        if (miniDescription !== undefined) course.miniDescription = miniDescription.trim();
        if (category) course.category = category.trim();
        if (seller !== undefined) course.seller = seller ? seller.trim() : null;
        if (images) course.images = images;
        if (offlinePrice !== undefined) course.offlinePrice = parseFloat(offlinePrice);
        if (offlineOriginalPrice !== undefined) course.offlineOriginalPrice = parseFloat(offlineOriginalPrice);
        if (onlinePrice !== undefined) course.onlinePrice = parseFloat(onlinePrice);
        if (onlineOriginalPrice !== undefined) course.onlineOriginalPrice = parseFloat(onlineOriginalPrice);
        if (toolsLanguage !== undefined) course.toolsLanguage = toolsLanguage.map(tool => tool.trim());
        if (learn) course.learn = learn.map(point => point.trim());
        if (curriculum) {
            course.curriculum = curriculum.map(section => ({
                section: section.section.trim(),
                lectures: section.lectures.map(lecture => lecture.trim())
            }));
        }
        if (status) course.status = status;
        if (students !== undefined) course.students = parseInt(students);

        await course.save();
        await course.populate('createdBy', 'name email');

        res.json({
            success: true,
            message: 'Course updated successfully',
            data: {
                course
            }
        });

    } catch (error) {
        console.error('Update course error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid course ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});


// Get all course sellers
app.get('/api/courses/sellers', async (req, res) => {
    try {
        const sellers = await Course.distinct('seller', {
            isDeleted: false,
            seller: { $ne: null, $ne: '' }
        });

        res.json({
            success: true,
            data: {
                sellers: sellers.filter(seller => seller).sort()
            }
        });
    } catch (error) {
        console.error('Get sellers error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Delete course (soft delete)
app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const course = await Course.findOne({
            _id: req.params.id,
            isDeleted: false
        });

        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }

        // Soft delete
        await course.softDelete();

        res.json({
            success: true,
            message: 'Course deleted successfully'
        });

    } catch (error) {
        console.error('Delete course error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid course ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});



// Create new poster
app.post('/api/posters', authenticateAdmin, async (req, res) => {
    try {
        const {
            title,
            image,
            content,
            status = 'active'
        } = req.body;

        // Validate required fields
        if (!title || !image || !content) {
            return res.status(400).json({
                success: false,
                message: 'Title, image, and content are required'
            });
        }

        // Validate content array
        if (!Array.isArray(content) || content.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one content point is required'
            });
        }

        // Create new poster
        const poster = new Poster({
            title: title.trim(),
            image: image.trim(),
            content: content.map(point => point.trim()),
            status,
            createdBy: req.user.userId || req.user.adminId
        });

        await poster.save();

        // Populate createdBy field
        await poster.populate('createdBy', 'name email');

        res.status(201).json({
            success: true,
            message: 'Poster created successfully',
            data: {
                poster
            }
        });

    } catch (error) {
        console.error('Create poster error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get all posters (with pagination, search, and filtering)
app.get('/api/posters', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            status = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        // Build query
        let query = { isDeleted: false };

        // Search functionality
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { 'content': { $regex: search, $options: 'i' } }
            ];
        }

        // Status filter
        if (status) {
            query.status = status;
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Get posters with pagination
        const posters = await Poster.find(query)
            .populate('createdBy', 'name email')
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum);

        // Get total count for pagination
        const total = await Poster.countDocuments(query);
        const totalPages = Math.ceil(total / limitNum);

        res.json({
            success: true,
            data: {
                posters,
                pagination: {
                    currentPage: pageNum,
                    totalPages,
                    totalPosters: total,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1
                }
            }
        });

    } catch (error) {
        console.error('Get posters error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get single poster by ID
app.get('/api/posters/:id', async (req, res) => {
    try {
        const poster = await Poster.findOne({
            _id: req.params.id,
            isDeleted: false
        }).populate('createdBy', 'name email');

        if (!poster) {
            return res.status(404).json({
                success: false,
                message: 'Poster not found'
            });
        }

        res.json({
            success: true,
            data: {
                poster
            }
        });

    } catch (error) {
        console.error('Get poster error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid poster ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update poster
app.put('/api/posters/:id', authenticateAdmin, async (req, res) => {
    try {
        const {
            title,
            image,
            content,
            status
        } = req.body;

        const poster = await Poster.findOne({
            _id: req.params.id,
            isDeleted: false
        });

        if (!poster) {
            return res.status(404).json({
                success: false,
                message: 'Poster not found'
            });
        }

        // Update fields if provided
        if (title) poster.title = title.trim();
        if (image) poster.image = image.trim();
        if (content) poster.content = content.map(point => point.trim());
        if (status) poster.status = status;

        await poster.save();
        await poster.populate('createdBy', 'name email');

        res.json({
            success: true,
            message: 'Poster updated successfully',
            data: {
                poster
            }
        });

    } catch (error) {
        console.error('Update poster error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid poster ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Delete poster (soft delete)
app.delete('/api/posters/:id', authenticateAdmin, async (req, res) => {
    try {
        const poster = await Poster.findOne({
            _id: req.params.id,
            isDeleted: false
        });

        if (!poster) {
            return res.status(404).json({
                success: false,
                message: 'Poster not found'
            });
        }

        // Soft delete
        await poster.softDelete();

        res.json({
            success: true,
            message: 'Poster deleted successfully'
        });

    } catch (error) {
        console.error('Delete poster error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid poster ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Global error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});



// Submit Course Application
app.post('/api/applications/submit', async (req, res) => {
    try {
        const {
            name,
            phone,
            email,
            course,
            studyMode,
            message
        } = req.body;

        console.log('Course application submission:', {
            name: name?.substring(0, 20) + '...',
            email,
            course,
            studyMode
        });

        // Basic validation
        if (!name || !phone || !email || !course || !studyMode) {
            return res.status(400).json({
                success: false,
                message: 'All required fields must be filled: name, phone, email, course, study mode'
            });
        }

        // Check for duplicate applications (same email and course within last 24 hours)
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const existingApplication = await Application.findOne({
            email: email.toLowerCase().trim(),
            course,
            createdAt: { $gte: twentyFourHoursAgo }
        });

        if (existingApplication) {
            return res.status(400).json({
                success: false,
                message: 'You have already applied for this course recently. Please wait 24 hours before submitting another application.'
            });
        }

        // Create new application
        const application = new Application({
            name: name.trim(),
            phone: phone.trim(),
            email: email.toLowerCase().trim(),
            course,
            studyMode,
            message: message ? message.trim() : '',
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });

        await application.save();

        console.log('Course application submitted successfully:', application.applicationId);

        res.status(201).json({
            success: true,
            message: 'Application submitted successfully! We will contact you soon.',
            data: {
                application: application.getFormattedApplication(),
                applicationId: application.applicationId
            }
        });

    } catch (error) {
        console.error('Application submission error:', error);

        // Mongoose validation error
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => ({
                field: err.path,
                message: err.message
            }));

            return res.status(400).json({
                success: false,
                message: 'Application validation failed',
                errors: errors
            });
        }

        // Duplicate application ID error (should be very rare)
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Duplicate application detected. Please try again.'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to submit application. Please try again later.'
        });
    }
});

// Get all applications (Admin only)
app.get('/api/applications', authenticateAdmin, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            status = '',
            course = '',
            studyMode = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        // Build query
        let query = {};

        // Search functionality
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } },
                { applicationId: { $regex: search, $options: 'i' } }
            ];
        }

        // Status filter
        if (status) {
            query.status = status;
        }

        // Course filter
        if (course) {
            query.course = course;
        }

        // Study mode filter
        if (studyMode) {
            query.studyMode = studyMode;
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Get applications with pagination
        const applications = await Application.find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum);

        // Get total count for pagination
        const total = await Application.countDocuments(query);
        const totalPages = Math.ceil(total / limitNum);

        res.json({
            success: true,
            data: {
                applications,
                pagination: {
                    currentPage: pageNum,
                    totalPages,
                    totalApplications: total,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1
                }
            }
        });

    } catch (error) {
        console.error('Get applications error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch applications'
        });
    }
});

// Get single application by ID (Admin only)
app.get('/api/applications/:id', authenticateAdmin, async (req, res) => {
    try {
        const application = await Application.findOne({
            $or: [
                { _id: req.params.id },
                { applicationId: req.params.id }
            ]
        });

        if (!application) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }

        res.json({
            success: true,
            data: {
                application: application.getFormattedApplication()
            }
        });

    } catch (error) {
        console.error('Get application error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to fetch application'
        });
    }
});

// Update application status (Admin only)
app.put('/api/applications/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;

        if (!status) {
            return res.status(400).json({
                success: false,
                message: 'Status is required'
            });
        }

        const application = await Application.findOne({
            $or: [
                { _id: req.params.id },
                { applicationId: req.params.id }
            ]
        });

        if (!application) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }

        application.status = status;
        if (adminNotes) {
            application.adminNotes = adminNotes;
        }

        await application.save();

        res.json({
            success: true,
            message: 'Application status updated successfully',
            data: {
                application: application.getFormattedApplication()
            }
        });

    } catch (error) {
        console.error('Update application status error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to update application status'
        });
    }
});

// Get application statistics (Admin only)
app.get('/api/applications/stats/overview', authenticateAdmin, async (req, res) => {
    try {
        const totalApplications = await Application.countDocuments();
        const pendingApplications = await Application.countDocuments({ status: 'pending' });
        const contactedApplications = await Application.countDocuments({ status: 'contacted' });
        const approvedApplications = await Application.countDocuments({ status: 'approved' });

        // Applications by course
        const applicationsByCourse = await Application.aggregate([
            {
                $group: {
                    _id: '$course',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);

        // Applications by study mode
        const applicationsByStudyMode = await Application.aggregate([
            {
                $group: {
                    _id: '$studyMode',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);

        // Recent applications (last 30 days)
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const recentApplications = await Application.countDocuments({
            createdAt: { $gte: thirtyDaysAgo }
        });

        res.json({
            success: true,
            data: {
                total: totalApplications,
                pending: pendingApplications,
                contacted: contactedApplications,
                approved: approvedApplications,
                recent: recentApplications,
                byCourse: applicationsByCourse,
                byStudyMode: applicationsByStudyMode
            }
        });

    } catch (error) {
        console.error('Get application stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch application statistics'
        });
    }
});




// Join Community Submission
app.post('/api/community/join', async (req, res) => {
    try {
        const {
            name,
            phone,
            email,
            skills,
            experienceLevel,
            yearsExperience,
            portfolioUrl,
            linkedinUrl
        } = req.body;

        console.log('Community join submission:', {
            name: name?.substring(0, 20) + '...',
            email,
            experienceLevel,
            skillsCount: skills?.length || 0,
            portfolioUrl: portfolioUrl ? 'provided' : 'not provided',
            linkedinUrl: linkedinUrl ? 'provided' : 'not provided'
        });

        // Basic validation
        if (!name || !phone || !email || !skills || !experienceLevel) {
            return res.status(400).json({
                success: false,
                message: 'All required fields must be filled: name, phone, email, skills, experience level'
            });
        }

        // Validate skills array
        if (!Array.isArray(skills) || skills.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one skill is required'
            });
        }

        // Validate experience level
        const validExperienceLevels = ['fresher', 'experienced'];
        if (!validExperienceLevels.includes(experienceLevel)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid experience level'
            });
        }

        // Validate years of experience for experienced level
        if (experienceLevel === 'experienced' && (!yearsExperience || yearsExperience < 1)) {
            return res.status(400).json({
                success: false,
                message: 'Valid years of experience is required for experienced level'
            });
        }

        // Validate URLs if provided
        if (portfolioUrl) {
            const urlRegex = /^https?:\/\/.+\..+/;
            if (!urlRegex.test(portfolioUrl)) {
                return res.status(400).json({
                    success: false,
                    message: 'Please provide a valid portfolio URL'
                });
            }
        }

        if (linkedinUrl) {
            const linkedinRegex = /^https?:\/\/(www\.)?linkedin\.com\/in\/.+/;
            if (!linkedinRegex.test(linkedinUrl)) {
                return res.status(400).json({
                    success: false,
                    message: 'Please provide a valid LinkedIn URL (should be in format: https://linkedin.com/in/username)'
                });
            }
        }

        // Check for duplicate submissions (same email or phone within last 24 hours)
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const existingSubmission = await Community.findOne({
            $or: [
                { email: email.toLowerCase() },
                { phone: phone }
            ],
            createdAt: { $gte: twentyFourHoursAgo }
        });

        if (existingSubmission) {
            return res.status(400).json({
                success: false,
                message: 'You have already submitted a community join request recently. Please wait 24 hours before submitting another request.'
            });
        }

        // Create new community submission
        const communitySubmission = new Community({
            name: name.trim(),
            phone: phone.trim(),
            email: email.toLowerCase().trim(),
            skills: skills.map(skill => skill.trim()),
            experienceLevel,
            yearsExperience: experienceLevel === 'experienced' ? parseInt(yearsExperience) : undefined,
            portfolioUrl: portfolioUrl ? portfolioUrl.trim() : undefined,
            linkedinUrl: linkedinUrl ? linkedinUrl.trim() : undefined,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });

        await communitySubmission.save();

        console.log('Community join request submitted successfully:', communitySubmission._id);

        res.status(201).json({
            success: true,
            message: 'Thank you for joining our community! We will contact you soon.',
            data: {
                submission: communitySubmission.formattedCommunity
            }
        });

    } catch (error) {
        console.error('Community join submission error:', error);

        // Mongoose validation error
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => ({
                field: err.path,
                message: err.message
            }));

            return res.status(400).json({
                success: false,
                message: 'Submission validation failed',
                errors: errors
            });
        }

        // Duplicate key error (if any unique constraints)
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Duplicate submission detected'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to submit community join request. Please try again later.'
        });
    }
});

// Get all community submissions (Admin only)
app.get('/api/community/submissions', authenticateAdmin, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            status = '',
            experienceLevel = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        // Build query
        let query = {};

        // Search functionality
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } },
                { skills: { $in: [new RegExp(search, 'i')] } }
            ];
        }

        // Status filter
        if (status) {
            query.status = status;
        }

        // Experience level filter
        if (experienceLevel) {
            query.experienceLevel = experienceLevel;
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Get submissions with pagination
        const submissions = await Community.find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum);

        // Get total count for pagination
        const total = await Community.countDocuments(query);
        const totalPages = Math.ceil(total / limitNum);

        res.json({
            success: true,
            data: {
                submissions,
                pagination: {
                    currentPage: pageNum,
                    totalPages,
                    totalSubmissions: total,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1
                }
            }
        });

    } catch (error) {
        console.error('Get community submissions error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch community submissions'
        });
    }
});

// Get single community submission by ID (Admin only)
app.get('/api/community/submissions/:id', authenticateAdmin, async (req, res) => {
    try {
        const submission = await Community.findById(req.params.id);

        if (!submission) {
            return res.status(404).json({
                success: false,
                message: 'Community submission not found'
            });
        }

        res.json({
            success: true,
            data: {
                submission: submission.formattedCommunity
            }
        });

    } catch (error) {
        console.error('Get community submission error:', error);

        if (error.name === 'CastError') {
            return res.status(400).json({
                success: false,
                message: 'Invalid submission ID'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to fetch community submission'
        });
    }
});

// Update community submission status (Admin only)
app.put('/api/community/submissions/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { status, notes } = req.body;

        if (!status) {
            return res.status(400).json({
                success: false,
                message: 'Status is required'
            });
        }

        const submission = await Community.findById(req.params.id);

        if (!submission) {
            return res.status(404).json({
                success: false,
                message: 'Community submission not found'
            });
        }

        await submission.updateStatus(status, notes);

        res.json({
            success: true,
            message: 'Community submission status updated successfully',
            data: {
                submission: submission.formattedCommunity
            }
        });

    } catch (error) {
        console.error('Update community submission status error:', error);

        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to update community submission status'
        });
    }
});

// Get community statistics (Admin only)
app.get('/api/community/stats/overview', authenticateAdmin, async (req, res) => {
    try {
        const totalSubmissions = await Community.countDocuments();
        const pendingSubmissions = await Community.countDocuments({ status: 'pending' });
        const contactedSubmissions = await Community.countDocuments({ status: 'contacted' });
        const approvedSubmissions = await Community.countDocuments({ status: 'approved' });

        // Submissions by experience level
        const submissionsByExperience = await Community.aggregate([
            {
                $group: {
                    _id: '$experienceLevel',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);

        // Top skills
        const topSkills = await Community.aggregate([
            { $unwind: '$skills' },
            {
                $group: {
                    _id: '$skills',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);

        // Portfolio and LinkedIn stats
        const portfolioStats = await Community.aggregate([
            {
                $group: {
                    _id: { $cond: [{ $ifNull: ['$portfolioUrl', false] }, 'withPortfolio', 'withoutPortfolio'] },
                    count: { $sum: 1 }
                }
            }
        ]);

        const linkedinStats = await Community.aggregate([
            {
                $group: {
                    _id: { $cond: [{ $ifNull: ['$linkedinUrl', false] }, 'withLinkedIn', 'withoutLinkedIn'] },
                    count: { $sum: 1 }
                }
            }
        ]);

        // Recent submissions (last 30 days)
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const recentSubmissions = await Community.countDocuments({
            createdAt: { $gte: thirtyDaysAgo }
        });

        res.json({
            success: true,
            data: {
                total: totalSubmissions,
                pending: pendingSubmissions,
                contacted: contactedSubmissions,
                approved: approvedSubmissions,
                recent: recentSubmissions,
                byExperience: submissionsByExperience,
                topSkills: topSkills,
                portfolioStats: portfolioStats,
                linkedinStats: linkedinStats
            }
        });

    } catch (error) {
        console.error('Get community stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch community statistics'
        });
    }
});



// Store Quiz Redeem Code
app.post('/api/quiz/redeem', async (req, res) => {
    try {
        const {
            userId,
            userName,
            userEmail,
            score,
            totalQuestions,
            redeemCode,
            quizType = 'general'
        } = req.body;

        console.log('Quiz redeem code submission:', {
            userId: userId?.substring(0, 10) + '...',
            userName: userName?.substring(0, 20) + '...',
            userEmail,
            score,
            totalQuestions,
            redeemCode
        });

        // Basic validation
        if (!userId || !userName || !userEmail || !redeemCode) {
            return res.status(400).json({
                success: false,
                message: 'User ID, name, email, and redeem code are required'
            });
        }

        // Validate score and totalQuestions
        if (score === undefined || totalQuestions === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Score and total questions are required'
            });
        }

        // Calculate percentage
        const percentage = Math.round((parseInt(score) / parseInt(totalQuestions)) * 100);

        // Create new quiz redeem record
        const quizRedeem = new QuizRedeem({
            userId: userId,
            userName: userName.trim(),
            userEmail: userEmail.toLowerCase().trim(),
            score: parseInt(score),
            totalQuestions: parseInt(totalQuestions),
            redeemCode: redeemCode.trim(),
            quizType: quizType,
            percentage: percentage,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });

        await quizRedeem.save();

        console.log('Quiz redeem code stored successfully:', quizRedeem._id);

        res.status(201).json({
            success: true,
            message: 'Redeem code stored successfully',
            data: {
                redeemId: quizRedeem._id,
                redeemCode: quizRedeem.redeemCode,
                score: quizRedeem.score,
                totalQuestions: quizRedeem.totalQuestions,
                percentage: quizRedeem.percentage,
                createdAt: quizRedeem.createdAt
            }
        });

    } catch (error) {
        console.error('Store quiz redeem code error:', error);

        // Mongoose validation error
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => ({
                field: err.path,
                message: err.message
            }));

            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors
            });
        }

        // Duplicate key error
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Redeem code already exists for this user'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to store redeem code. Please try again later.'
        });
    }
});

// Get all quiz redeem codes (Admin only)
app.get('/api/quiz/redeem', authenticateAdmin, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            quizType = '',
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        // Build query
        let query = {};

        // Search functionality
        if (search) {
            query.$or = [
                { userName: { $regex: search, $options: 'i' } },
                { userEmail: { $regex: search, $options: 'i' } },
                { redeemCode: { $regex: search, $options: 'i' } }
            ];
        }

        // Quiz type filter
        if (quizType) {
            query.quizType = quizType;
        }

        // Sort options
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

        // Get redeems with pagination
        const redeems = await QuizRedeem.find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum);

        // Get total count for pagination
        const total = await QuizRedeem.countDocuments(query);
        const totalPages = Math.ceil(total / limitNum);

        res.json({
            success: true,
            data: {
                redeems,
                pagination: {
                    currentPage: pageNum,
                    totalPages,
                    totalRedeems: total,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1
                }
            }
        });

    } catch (error) {
        console.error('Get quiz redeems error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch redeem codes'
        });
    }
});

// Get quiz redeem codes for specific user
app.get('/api/quiz/redeem/user/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;

        // Verify the authenticated user is accessing their own data
        if (req.user.userId !== userId && req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }

        const redeems = await QuizRedeem.find({ userId: userId })
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            data: {
                redeems,
                total: redeems.length
            }
        });

    } catch (error) {
        console.error('Get user quiz redeems error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch redeem codes'
        });
    }
});




// 404 handler for undefined routes
app.use((req, res) => {
    if (req.url.startsWith('/api/')) {
        // API routes should return 404
        return res.status(404).json({
            success: false,
            message: 'API route not found'
        });
    }

    // For non-API routes, you might want to serve your frontend
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Server setup
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
});