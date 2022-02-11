const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let userSchema = new Schema({
    fullName: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
        index: true,
        unique: true,
    },
    email: {
        type: String,
        required: true,
        index: true,
        unique: true,
    },
    emailVarifiedAt: {
        type: Date,
        required: false,
    },
    password: {
        type: String,
        required: true,
    },
    avatar: {
        type: String,
        required: false,
    },
    role: {
        type: String,
        enum: ['user', 'administrator'],
        default: 'user'
    },
    tokens: [{
        token: {
            type: String,
            required: false,
        }
    }],
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

module.exports = User;