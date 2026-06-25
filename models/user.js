const mongoose = require('mongoose');

const fileSchema = mongoose.Schema({
  originalName: String,
  mimetype: String,
  size: Number,
  fileData: Buffer,
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

const userSchema = mongoose.Schema({
  image : String,
  email: String,
  name : String,
  password: String,
  files: [fileSchema]
});

module.exports = mongoose.model('User', userSchema);