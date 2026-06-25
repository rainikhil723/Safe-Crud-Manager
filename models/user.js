const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/testapp1')

const fileSchema = mongoose.Schema({
  originalName: String,
  storedName: String,
  path: String,
  mimetype: String,
  size: Number,
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
  