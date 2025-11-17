const mongoose = require('mongoose');

const quizRedeemSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    userName: {
        type: String,
        required: true,
        trim: true
    },
    userEmail: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    score: {
        type: Number,
        required: true,
        min: 0
    },
    totalQuestions: {
        type: Number,
        required: true,
        min: 1
    },
    percentage: {
        type: Number,
        required: true,
        min: 0,
        max: 100
    },
    redeemCode: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    quizType: {
        type: String,
        required: true,
        default: 'programming_math',
        enum: ['programming_math', 'general_knowledge', 'technical']
    },
    isUsed: {
        type: Boolean,
        default: false
    },
    usedAt: {
        type: Date
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    }
}, {
    timestamps: true
});

// Index for better query performance
quizRedeemSchema.index({ userId: 1, createdAt: -1 });
quizRedeemSchema.index({ redeemCode: 1 });
quizRedeemSchema.index({ userEmail: 1 });
quizRedeemSchema.index({ createdAt: -1 });

// Method to mark redeem code as used
quizRedeemSchema.methods.markAsUsed = function() {
    this.isUsed = true;
    this.usedAt = new Date();
    return this.save();
};

// Static method to get redeem code by code
quizRedeemSchema.statics.findByCode = function(code) {
    return this.findOne({ redeemCode: code });
};

// Static method to get user's redeem codes
quizRedeemSchema.statics.findByUserId = function(userId) {
    return this.find({ userId: userId }).sort({ createdAt: -1 });
};

// Virtual for formatted data
quizRedeemSchema.virtual('formattedRedeem').get(function() {
    return {
        id: this._id,
        userId: this.userId,
        userName: this.userName,
        userEmail: this.userEmail,
        score: this.score,
        totalQuestions: this.totalQuestions,
        percentage: this.percentage,
        redeemCode: this.redeemCode,
        quizType: this.quizType,
        isUsed: this.isUsed,
        usedAt: this.usedAt,
        createdAt: this.createdAt
    };
});

module.exports = mongoose.model('QuizRedeem', quizRedeemSchema);