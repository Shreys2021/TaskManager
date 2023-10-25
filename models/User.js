// Import necessary modules and setup Mongoose
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Create a user schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true, // Ensure emails are stored in lowercase
        trim: true // Remove whitespace from the email
    },
    password: {
        type: String,
        required: true
    }
});

userSchema.methods.isValidPassword = async function (password) {
    try {
        console.log(password);
        console.log(this.password)
        const isPasswordValid = await bcrypt.compareSync(password, this.password);
        console.log(isPasswordValid); // Log the result
        console.log(isPasswordValid)
        return isPasswordValid;
    } catch (error) {
        throw error;
    }
};

// Hash the password before saving it to the database
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    const saltRounds = 10;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
});

// Create a User model using the schema
const User = mongoose.model('User', userSchema);

// Export the User model
module.exports = User;
