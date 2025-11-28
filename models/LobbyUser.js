const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const lobbyUserSchema = new mongoose.Schema({
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
        match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        trim: true,
        match: [/^\d{10}$/, 'Phone number must be 10 digits']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    role: {
        type: String,
        default: 'lobby_user',
        enum: ['lobby_user', 'lobby_admin']
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    loginCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Hash password before saving
lobbyUserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
lobbyUserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Update last login
lobbyUserSchema.methods.updateLastLogin = async function() {
    this.lastLogin = new Date();
    this.loginCount += 1;
    return await this.save();
};

// Get user profile (without password)
lobbyUserSchema.methods.getProfile = function() {
    return {
        id: this._id,
        name: this.name,
        email: this.email,
        phone: this.phone,
        role: this.role,
        isActive: this.isActive,
        lastLogin: this.lastLogin,
        loginCount: this.loginCount,
        createdAt: this.createdAt
    };
};

// Static method to find by email
lobbyUserSchema.statics.findByEmail = function(email) {
    return this.findOne({ email: email.toLowerCase().trim() });
};

module.exports = mongoose.model('LobbyUser', lobbyUserSchema);