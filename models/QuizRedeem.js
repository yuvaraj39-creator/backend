const mongoose = require('mongoose');

const quizRedeemSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        trim: true
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
        default: 'general',
        trim: true
    },
    ipAddress: {
        type: String,
        trim: true
    },
    userAgent: {
        type: String,
        trim: true
    }
}, {
    timestamps: true
});

// Index for better query performance
quizRedeemSchema.index({ userId: 1, createdAt: -1 });
quizRedeemSchema.index({ userEmail: 1 });
quizRedeemSchema.index({ redeemCode: 1 });

const QuizRedeem = mongoose.model('QuizRedeem', quizRedeemSchema);

module.exports = QuizRedeem;