const mongoose = require('mongoose');

const authSchema = mongoose.Schema({
    email: String,
    password: String
});

module.exports = mongoose.model('Auth', authSchema);