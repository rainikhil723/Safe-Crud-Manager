const express = require('express');
const app = express();
const path = require('path');
const multer = require('multer');
const userModel = require('./models/user');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authModel = require('./models/auth');

const APP_AUTH_SECRET = 'your_secret_key';
const USER_ACCESS_SECRET = 'user_profile_access_secret';

const storage = multer.memoryStorage();
const upload = multer({ storage });

function isLoggedIn(req, res, next) {
  if (!req.cookies.token) return res.redirect('/login');

  try {
    const data = jwt.verify(req.cookies.token, APP_AUTH_SECRET);
    req.user = data;
    next();
  } catch (err) {
    res.redirect('/login');
  }
}

function verifyUserAccess(req, res, next) {
  const tokenFromBody = req.body ? req.body.userAccessToken : undefined;
  const tokenFromQuery = req.query ? req.query.userAccessToken : undefined;
  const userAccessToken = tokenFromBody || tokenFromQuery;

  if (!userAccessToken) return res.redirect('/read');

  try {
    const accessData = jwt.verify(userAccessToken, USER_ACCESS_SECRET);
    req.userAccess = accessData;
    req.userAccessToken = userAccessToken;
    next();
  } catch (err) {
    return res.redirect('/read');
  }
}

app.set('view engine','ejs');
app.use(express.json());
app.use(express.urlencoded({extended : true}));
app.use(express.static(path.join(__dirname,'public')));
app.use(cookieParser());

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await authModel.findOne({ email });
  if (!user) return res.status(401).render('wrong-login');

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).render('wrong-login');

  const token = jwt.sign(
    { email: user.email, id: user._id },
    APP_AUTH_SECRET
  );

  res.cookie('token', token);
  res.redirect('/read');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  
  await authModel.create({
    email,
    password: hashedPassword
  });
  
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/hacker-busted', (req, res) => {
  res.render('hacker-busted');
});

app.get('/', (req,res) => {
    res.render('index');
});

app.get('/read', isLoggedIn, async(req,res) => {
    let users = await userModel.find();
    res.render('read',{users});
});

app.post('/user/:id/open', isLoggedIn, async (req, res) => {
  const { password } = req.body;
  const user = await userModel.findById(req.params.id);

  if (!user || !user.password) return res.status(401).render('wrong-login');

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).render('wrong-login');

  const userAccessToken = jwt.sign(
    { userId: user._id.toString() },
    USER_ACCESS_SECRET,
    { expiresIn: '20m' }
  );

  res.redirect(`/user/${user._id}?userAccessToken=${encodeURIComponent(userAccessToken)}`);
});

app.get('/user/:id', isLoggedIn, verifyUserAccess, async (req, res) => {
  if (req.userAccess.userId !== req.params.id) return res.redirect('/read');

  const user = await userModel.findById(req.params.id);
  if (!user) return res.redirect('/read');

  res.render('user-details', { user, userAccessToken: req.userAccessToken });
});

app.post('/user/:id/update', isLoggedIn, verifyUserAccess, async (req, res) => {
  if (req.userAccess.userId !== req.params.id) return res.redirect('/read');

  const { image, email, name, password } = req.body;
  const updateData = { image, email, name };

  if (password && password.trim()) {
    const salt = await bcrypt.genSalt(10);
    updateData.password = await bcrypt.hash(password, salt);
  }

  await userModel.findByIdAndUpdate(req.params.id, updateData, { new: true });
  res.redirect(`/user/${req.params.id}?userAccessToken=${encodeURIComponent(req.userAccessToken)}`);
});

app.post('/user/:id/upload', isLoggedIn, verifyUserAccess, upload.single('userFile'), async (req, res) => {
  if (req.userAccess.userId !== req.params.id) return res.redirect('/read');
  if (!req.file) {
    return res.redirect(`/user/${req.params.id}?userAccessToken=${encodeURIComponent(req.userAccessToken)}`);
  }

  await userModel.findByIdAndUpdate(
    req.params.id,
    {
      $push: {
        files: {
          originalName: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size,
          fileData: req.file.buffer,
          uploadedAt: new Date()
        }
      }
    },
    { new: true }
  );

  res.redirect(`/user/${req.params.id}?userAccessToken=${encodeURIComponent(req.userAccessToken)}`);
});

app.get('/user/:id/files', isLoggedIn, verifyUserAccess, async (req, res) => {
  if (req.userAccess.userId !== req.params.id) return res.redirect('/read');

  const user = await userModel.findById(req.params.id);
  if (!user) return res.redirect('/read');

  res.render('user-files', { user, userAccessToken: req.userAccessToken });
});

app.get('/user/:userId/file/:fileId', isLoggedIn, verifyUserAccess, async (req, res) => {
  if (req.userAccess.userId !== req.params.userId) return res.redirect('/read');

  const user = await userModel.findById(req.params.userId);
  if (!user) return res.status(404).send('User not found');

  const file = user.files.id(req.params.fileId);
  if (!file) return res.status(404).send('File not found');

  res.set({
    'Content-Type': file.mimetype,
    'Content-Disposition': `inline; filename="${file.originalName}"`
  });
  res.send(file.fileData);
});

app.post('/user/:userId/file/:fileId/delete', isLoggedIn, verifyUserAccess, async (req, res) => {
  if (req.userAccess.userId !== req.params.userId) return res.redirect('/read');

  await userModel.findByIdAndUpdate(
    req.params.userId,
    {
      $pull: { files: { _id: req.params.fileId } }
    }
  );

  res.redirect(`/user/${req.params.userId}/files?userAccessToken=${encodeURIComponent(req.userAccessToken)}`);
});

app.post('/delete/:id', isLoggedIn, async (req, res) => {
  await userModel.findByIdAndDelete(req.params.id);
  res.redirect('/read');
});

app.get('/edit/:id', isLoggedIn, async (req, res) => {
  let user = await userModel.findById(req.params.id);
  if (!user) return res.redirect('/read');
  res.render('edit', { users: user });
});

app.post('/create', isLoggedIn, async (req,res) => {
  let {image,email,name,password} = req.body;

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  await userModel.create({
        name,
        email,
    image,
    password: hashedPassword
    });
   res.redirect('/read');
});

app.listen(4000);