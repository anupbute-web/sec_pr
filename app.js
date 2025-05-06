const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const validator = require('validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your_jwt_secret'; 

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Connect DB
mongoose.connect('mongodb://127.0.0.1:27017/mySecretsApp', { useNewUrlParser: true, useUnifiedTopology: true });

// Mongoose User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});
const User = mongoose.model('User', userSchema);

// Auth Middleware
function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!validator.isEmail(email)) {
    return res.send('Invalid email format');
  }

  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.send('Password must contain uppercase, lowercase, number, and be 6+ characters');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await User.create({ name, email, password: hashedPassword });
    res.redirect('/login');
  } catch (err) {
    res.send('User already exists or error occurred');
  }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!validator.isEmail(email)) return res.send('Invalid email'); 
  
  const user = await User.findOne({ email });
  if (!user) return res.send('User not found');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send('Invalid credentials');

  const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1h' });

  res.cookie('token', token, { httpOnly: true, secure: true });
  res.redirect('/secrets');
});

app.get('/secrets', authenticate, (req, res) => {
  res.render('secret', { user: req.user });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
