const mongoose = require('mongoose');

const OTPSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true
    },
    otp: {
        type: String,
        required: true
    },
    purpose: {
        type: String,
        required: true,
        enum: ['password_reset', 'email_verification', 'account_verification'],
        default: 'password_reset'
    },
    expiresAt: {
        type: Date,
        required: true
    },
    attempts: {
        type: Number,
        default: 0
    },
    verified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Index for automatic expiry
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Index for email and purpose queries
OTPSchema.index({ email: 1, purpose: 1 });

// Static method to create OTP
OTPSchema.statics.createOTP = async function(email, purpose = 'password_reset') {
    try {
        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Create OTP document
        const otpDoc = new this({
            email: email.toLowerCase().trim(),
            otp,
            purpose,
            expiresAt
        });

        await otpDoc.save();
        return otpDoc;
    } catch (error) {
        throw error;
    }
};

// Static method to verify OTP
OTPSchema.statics.verifyOTP = async function(email, otp, purpose = 'password_reset') {
    try {
        const otpDoc = await this.findOne({
            email: email.toLowerCase().trim(),
            purpose,
            expiresAt: { $gt: new Date() },
            verified: false
        });

        if (!otpDoc) {
            return {
                success: false,
                message: 'OTP not found or expired'
            };
        }

        // Check attempts
        if (otpDoc.attempts >= 5) {
            await this.deleteOne({ _id: otpDoc._id });
            return {
                success: false,
                message: 'Maximum OTP attempts exceeded'
            };
        }

        // Verify OTP
        if (otpDoc.otp !== otp) {
            otpDoc.attempts += 1;
            await otpDoc.save();
            
            const remainingAttempts = 5 - otpDoc.attempts;
            return {
                success: false,
                message: `Invalid OTP. ${remainingAttempts} attempts remaining`
            };
        }

        // Mark as verified
        otpDoc.verified = true;
        await otpDoc.save();

        return {
            success: true,
            message: 'OTP verified successfully',
            otpDoc
        };
    } catch (error) {
        throw error;
    }
};

// Static method to get valid OTP
OTPSchema.statics.getValidOTP = async function(email, purpose = 'password_reset') {
    try {
        return await this.findOne({
            email: email.toLowerCase().trim(),
            purpose,
            expiresAt: { $gt: new Date() },
            verified: false
        });
    } catch (error) {
        throw error;
    }
};

// Static method to delete OTP
OTPSchema.statics.deleteOTP = async function(email, purpose = 'password_reset') {
    try {
        await this.deleteMany({
            email: email.toLowerCase().trim(),
            purpose
        });
    } catch (error) {
        throw error;
    }
};

// Static method to cleanup expired OTPs
OTPSchema.statics.cleanupExpired = async function() {
    try {
        const result = await this.deleteMany({
            expiresAt: { $lt: new Date() }
        });
        console.log(`Cleaned up ${result.deletedCount} expired OTPs`);
        return result;
    } catch (error) {
        throw error;
    }
};

// Instance method to check if OTP is expired
OTPSchema.methods.isExpired = function() {
    return this.expiresAt < new Date();
};

// Instance method to check if maximum attempts reached
OTPSchema.methods.isMaxAttemptsReached = function() {
    return this.attempts >= 5;
};

// Instance method to increment attempts
OTPSchema.methods.incrementAttempts = async function() {
    this.attempts += 1;
    return await this.save();
};

// Instance method to mark as verified
OTPSchema.methods.markAsVerified = async function() {
    this.verified = true;
    return await this.save();
};

module.exports = mongoose.model('OTP', OTPSchema);