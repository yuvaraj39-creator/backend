const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        validate: {
            validator: function (email) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            },
            message: 'Please enter a valid email address'
        }
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        validate: {
            validator: function (phone) {
                return /^\d{10}$/.test(phone);
            },
            message: 'Phone number must be exactly 10 digits'
        }
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
        // Removed complex password validation for now to fix registration issues
    },
    experience: {
        type: String,
        required: [true, 'Experience level is required'],
        enum: {
            values: [
                'Working professional – Technical roles',
                'Working professional – Non-technical',
                'College student – Final year',
                'Internship',
                'Others'
            ],
            message: 'Please select a valid experience level'
        }
    },
    additionalInfo: {
        type: String,
        trim: true,
        maxlength: [500, 'Additional information cannot exceed 500 characters']
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    lastLogin: Date,
    loginCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true // Adds createdAt and updatedAt automatically
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ createdAt: -1 });

// Pre-save middleware to hash password before saving
userSchema.pre('save', async function (next) {
    // Only hash the password if it's modified (or new) and not already hashed
    if (!this.isModified('password')) {
        return next();
    }

    // Check if password is already hashed (starts with bcrypt identifier)
    if (this.password.startsWith('$2a$') || this.password.startsWith('$2b$')) {
        return next();
    }

    // Basic password length validation
    if (this.password.length < 6) {
        const error = new Error('Password must be at least 6 characters long');
        error.name = 'ValidationError';
        return next(error);
    }

    try {
        // Generate salt
        const salt = await bcrypt.genSalt(12);
        // Hash password
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password for login
userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new Error('Password comparison failed');
    }
};

// Method to update last login
userSchema.methods.updateLastLogin = async function () {
    this.lastLogin = new Date();
    this.loginCount += 1;
    return await this.save();
};

// Method to get user profile (without sensitive data)
userSchema.methods.getProfile = function () {
    return {
        id: this._id,
        name: this.name,
        email: this.email,
        phone: this.phone,
        experience: this.experience,
        additionalInfo: this.additionalInfo,
        role: this.role,
        isVerified: this.isVerified,
        createdAt: this.createdAt,
        lastLogin: this.lastLogin,
        loginCount: this.loginCount
    };
};

// Static method to find user by email
userSchema.statics.findByEmail = function (email) {
    return this.findOne({ email: email.toLowerCase() });
};

// Static method to find user by phone
userSchema.statics.findByPhone = function (phone) {
    return this.findOne({ phone });
};

// Virtual for user's display name
userSchema.virtual('displayName').get(function () {
    return this.name;
});

// Transform output to remove sensitive data
userSchema.set('toJSON', {
    transform: function (doc, ret) {
        delete ret.password;
        delete ret.resetPasswordToken;
        delete ret.resetPasswordExpire;
        return ret;
    }
});

// Update updatedAt timestamp before update
userSchema.pre('findOneAndUpdate', function (next) {
    this.set({ updatedAt: new Date() });
    next();
});

module.exports = mongoose.model('User', userSchema);