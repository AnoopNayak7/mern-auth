const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Please enter your name"],
        trim: true
    },
    email: {
        type: String,
        required: [true, "Please enter your email"],
        trim: true,
        unique: true
    },
    password: {
        type: String,
        required: [true, "Please enter your password"],
        trim: true,
    },
    profile_photo: {
        type: String,
        required: false,
    }
},{
    timestamps: true
})

module.exports = mongoose.model("User", userSchema)