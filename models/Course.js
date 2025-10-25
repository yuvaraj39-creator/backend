const mongoose = require('mongoose');

const curriculumSchema = new mongoose.Schema({
    section: {
        type: String,
        required: true,
        trim: true
    },
    lectures: [{
        type: String,
        required: true,
        trim: true
    }]
});

const courseSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Course title is required'],
        trim: true,
        maxlength: [200, 'Title cannot exceed 200 characters']
    },
    description: {
        type: String,
        required: [true, 'Course description is required'],
        trim: true,
        maxlength: [2000, 'Description cannot exceed 2000 characters']
    },
    miniDescription: {
        type: String,
        trim: true,
        maxlength: [200, 'Mini description cannot exceed 200 characters']
    },
    category: {
        type: String,
        required: [true, 'Course category is required'],
        trim: true
    },
    seller: {
        type: String,
        trim: true
    },
    images: [{
        type: String,
        required: [true, 'At least one course image is required'],
        validate: {
            validator: function (url) {
                try {
                    new URL(url);
                    return true;
                } catch (_) {
                    return false;
                }
            },
            message: 'Invalid image URL'
        }
    }],
    offlinePrice: {
        type: Number,
        required: [true, 'Offline price is required'],
        min: [0, 'Price cannot be negative']
    },
    offlineOriginalPrice: {
        type: Number,
        min: [0, 'Price cannot be negative']
    },
    onlinePrice: {
        type: Number,
        required: [true, 'Online price is required'],
        min: [0, 'Price cannot be negative']
    },
    onlineOriginalPrice: {
        type: Number,
        min: [0, 'Price cannot be negative']
    },
    toolsLanguage: [{
        type: String,
        trim: true
    }],
    students: {
        type: Number,
        default: 0,
        min: [0, 'Student count cannot be negative']
    },
    status: {
        type: String,
        enum: ['active', 'draft', 'archived'],
        default: 'draft'
    },
    learn: [{
        type: String,
        required: true,
        trim: true
    }],
    curriculum: [curriculumSchema],
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    isDeleted: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// Index for search functionality (updated to include category and seller)
courseSchema.index({
    title: 'text',
    description: 'text',
    'learn': 'text',
    'toolsLanguage': 'text',
    'category': 'text',
    'seller': 'text'
});

// Virtual for discount percentage
courseSchema.virtual('onlineDiscountPercentage').get(function () {
    if (this.onlineOriginalPrice && this.onlineOriginalPrice > this.onlinePrice) {
        return Math.round(((this.onlineOriginalPrice - this.onlinePrice) / this.onlineOriginalPrice) * 100);
    }
    return 0;
});

courseSchema.virtual('offlineDiscountPercentage').get(function () {
    if (this.offlineOriginalPrice && this.offlineOriginalPrice > this.offlinePrice) {
        return Math.round(((this.offlineOriginalPrice - this.offlinePrice) / this.offlineOriginalPrice) * 100);
    }
    return 0;
});

// Method to soft delete
courseSchema.methods.softDelete = function () {
    this.isDeleted = true;
    return this.save();
};

// Static method to find active courses
courseSchema.statics.findActive = function () {
    return this.find({ status: 'active', isDeleted: false });
};

// Static method to search courses (updated to include category and seller)
courseSchema.statics.search = function (query) {
    return this.find({
        $and: [
            { isDeleted: false },
            {
                $or: [
                    { title: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } },
                    { 'learn': { $regex: query, $options: 'i' } },
                    { 'toolsLanguage': { $regex: query, $options: 'i' } },
                    { 'category': { $regex: query, $options: 'i' } },
                    { 'seller': { $regex: query, $options: 'i' } }
                ]
            }
        ]
    });
};

// Ensure virtual fields are serialized
courseSchema.set('toJSON', {
    virtuals: true,
    transform: function (doc, ret) {
        delete ret.__v;
        delete ret.isDeleted;
        return ret;
    }
});

module.exports = mongoose.model('Course', courseSchema);