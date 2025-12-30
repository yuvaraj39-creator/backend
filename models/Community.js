const mongoose = require('mongoose');

const communitySchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true,
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        trim: true,
        match: [/^[0-9+\-\s()]{10,15}$/, 'Please enter a valid phone number']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    skills: {
        type: [String],
        required: [true, 'At least one skill is required'],
        validate: {
            validator: function(skills) {
                return skills.length > 0;
            },
            message: 'At least one skill is required'
        }
    },
    experienceLevel: {
        type: String,
        required: [true, 'Experience level is required'],
        enum: {
            values: ['fresher', 'experienced'],
            message: 'Experience level must be either fresher or experienced'
        }
    },
    yearsExperience: {
        type: Number,
        min: [0, 'Years of experience cannot be negative'],
        max: [50, 'Years of experience cannot exceed 50'],
        validate: {
            validator: function(value) {
                if (this.experienceLevel === 'experienced') {
                    return value !== undefined && value !== null && value >= 1;
                }
                return true;
            },
            message: 'Years of experience is required for experienced level'
        }
    },
    // Updated: Replace resume file upload with URL fields
    portfolioUrl: {
        type: String,
        trim: true,
        match: [/^https?:\/\/.+\..+/, 'Please enter a valid URL']
    },
    linkedinUrl: {
        type: String,
        trim: true,
        match: [/^https?:\/\/(www\.)?linkedin\.com\/in\/.+/, 'Please enter a valid LinkedIn URL']
    },
    status: {
        type: String,
        enum: ['pending', 'contacted', 'approved', 'rejected','processing','completed','not-interested'],
        default: 'pending'
    },
    notes: {
        type: String,
        trim: true,
        maxlength: [500, 'Notes cannot exceed 500 characters']
    },
    ipAddress: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

// Index for better query performance
communitySchema.index({ email: 1 });
communitySchema.index({ status: 1 });
communitySchema.index({ createdAt: -1 });
communitySchema.index({ experienceLevel: 1 });

// Virtual for formatted response
communitySchema.virtual('formattedCommunity').get(function() {
    return {
        id: this._id,
        name: this.name,
        phone: this.phone,
        email: this.email,
        skills: this.skills,
        experienceLevel: this.experienceLevel,
        yearsExperience: this.yearsExperience,
        portfolioUrl: this.portfolioUrl,
        linkedinUrl: this.linkedinUrl,
        status: this.status,
        notes: this.notes,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
    };
});

// Ensure virtual fields are serialized
communitySchema.set('toJSON', { virtuals: true });

// Static method to check for duplicate submissions
communitySchema.statics.checkDuplicate = async function(email, phone) {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const existing = await this.findOne({
        $or: [
            { email: email.toLowerCase() },
            { phone: phone }
        ],
        createdAt: { $gte: twentyFourHoursAgo }
    });
    
    return existing;
};

// Instance method to update status
communitySchema.methods.updateStatus = function(status, notes = '') {
    this.status = status;
    if (notes) {
        this.notes = notes;
    }
    return this.save();
};

const Community = mongoose.model('Community', communitySchema);

module.exports = Community;