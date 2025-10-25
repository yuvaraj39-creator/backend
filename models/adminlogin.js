const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const adminLoginSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        default: 'admin',
        enum: ['admin']
    },
    name: {
        type: String,
        default: 'Admin User'
    },
    lastLogin: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

// Pre-save middleware to hash password
adminLoginSchema.pre('save', async function (next) {
    // Only hash the password if it's modified (or new)
    if (!this.isModified('password')) return next();

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

// Method to compare password
adminLoginSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to update last login
adminLoginSchema.methods.updateLastLogin = async function () {
    this.lastLogin = new Date();
    return await this.save();
};

// Method to get profile (without password)
adminLoginSchema.methods.getProfile = function () {
    return {
        _id: this._id,
        email: this.email,
        role: this.role,
        name: this.name,
        lastLogin: this.lastLogin,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
    };
};

// Static method to find by email
adminLoginSchema.statics.findByEmail = function (email) {
    return this.findOne({ email: email.toLowerCase().trim() });
};

// Create default admin if not exists
adminLoginSchema.statics.createDefaultAdmin = async function () {
    try {
        const defaultEmail = 'admin@u1technology.com';
        const defaultPassword = 'admin123';

        let existingAdmin = await this.findOne({ email: defaultEmail });

        if (!existingAdmin) {
            // Create new admin
            const defaultAdmin = new this({
                email: defaultEmail,
                password: defaultPassword,
                name: 'Administrator',
                role: 'admin'
            });

            await defaultAdmin.save();
            console.log('✅ Default admin user created successfully');
        } else {
            // Update existing admin to ensure it has correct role and name
            existingAdmin.name = 'Administrator';
            existingAdmin.role = 'admin';

            // Only update password if it's the default one (to avoid overwriting changed passwords)
            // You can remove this check if you want to always reset to default password
            const isDefaultPassword = await existingAdmin.comparePassword(defaultPassword);
            if (!isDefaultPassword) {
                console.log('ℹ️  Admin password has been changed, keeping current password');
            } else {
                existingAdmin.password = defaultPassword;
            }

            await existingAdmin.save();
            console.log('✅ Default admin user verified and updated');
        }
    } catch (error) {
        console.error('❌ Error creating/updating default admin:', error);
    }
};
const AdminLogin = mongoose.model('AdminLogin', adminLoginSchema);

module.exports = AdminLogin;