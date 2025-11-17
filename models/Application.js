const mongoose = require('mongoose');

const applicationSchema = new mongoose.Schema({
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
        match: [/^[0-9+\-\s()]{10,15}$/, 'Please provide a valid phone number']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
    },
    course: {
        type: String,
        required: [true, 'Course selection is required'],
        enum: {
            values: ['testing', 'fullstack', 'frontend', 'backend', 'datascience', 'ai-ml', 'cybersecurity', 'cloud', 'devops', 'mobile'],
            message: 'Please select a valid course'
        }
    },
    studyMode: {
        type: String,
        required: [true, 'Study mode is required'],
        enum: {
            values: ['online', 'offline', 'hybrid'],
            message: 'Please select a valid study mode'
        }
    },
    message: {
        type: String,
        trim: true,
        maxlength: [1000, 'Message cannot exceed 1000 characters']
    },
    status: {
        type: String,
        enum: ['pending', 'contacted', 'approved', 'rejected'],
        default: 'pending'
    },
    applicationId: {
        type: String,
        unique: true
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

// Generate application ID before saving
applicationSchema.pre('save', async function (next) {
    if (this.isNew) {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substr(2, 5);
        this.applicationId = `APP-${timestamp}-${random}`.toUpperCase();
    }
    next();
});

// Static method to get applications by status
applicationSchema.statics.getByStatus = function (status) {
    return this.find({ status }).sort({ createdAt: -1 });
};

// Static method to get applications by course
applicationSchema.statics.getByCourse = function (course) {
    return this.find({ course }).sort({ createdAt: -1 });
};

// Instance method to get formatted application
applicationSchema.methods.getFormattedApplication = function () {
    return {
        applicationId: this.applicationId,
        name: this.name,
        phone: this.phone,
        email: this.email,
        course: this.course,
        studyMode: this.studyMode,
        message: this.message,
        status: this.status,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
    };
};

// Virtual for formatted course name
applicationSchema.virtual('formattedCourse').get(function () {
    const courseMap = {
        'testing': 'Testing',
        'fullstack': 'Full Stack Development',
        'frontend': 'Frontend Development',
        'backend': 'Backend Development',
        'datascience': 'Data Science',
        'ai-ml': 'AI & Machine Learning',
        'cybersecurity': 'Cyber Security',
        'cloud': 'Cloud Computing',
        'devops': 'DevOps',
        'mobile': 'Mobile Development'
    };
    return courseMap[this.course] || this.course;
});

// Virtual for formatted study mode
applicationSchema.virtual('formattedStudyMode').get(function () {
    const modeMap = {
        'online': 'Online',
        'offline': 'Offline',
        'hybrid': 'Hybrid'
    };
    return modeMap[this.studyMode] || this.studyMode;
});

module.exports = mongoose.model('Application', applicationSchema);