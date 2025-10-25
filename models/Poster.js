const mongoose = require('mongoose');

const posterSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Poster title is required'],
        trim: true,
        maxlength: [200, 'Title cannot exceed 200 characters']
    },
    image: {
        type: String,
        required: [true, 'Poster image is required'],
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
    },
    content: [{
        type: String,
        required: true,
        trim: true
    }],
    status: {
        type: String,
        enum: ['active', 'draft', 'archived'],
        default: 'active'
    },
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

// Index for search functionality
posterSchema.index({
    title: 'text',
    'content': 'text'
});

// Method to soft delete
posterSchema.methods.softDelete = function () {
    this.isDeleted = true;
    return this.save();
};

// Static method to find active posters
posterSchema.statics.findActive = function () {
    return this.find({ status: 'active', isDeleted: false });
};

// Static method to search posters
posterSchema.statics.search = function (query) {
    return this.find({
        $and: [
            { isDeleted: false },
            {
                $or: [
                    { title: { $regex: query, $options: 'i' } },
                    { 'content': { $regex: query, $options: 'i' } }
                ]
            }
        ]
    });
};

// Ensure virtual fields are serialized
posterSchema.set('toJSON', {
    transform: function (doc, ret) {
        delete ret.__v;
        delete ret.isDeleted;
        return ret;
    }
});

module.exports = mongoose.model('Poster', posterSchema);