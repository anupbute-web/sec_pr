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

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");

const ejs = require("ejs");
const bcrypt = require("bcrypt");
const path = require("path");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60,
    },
  })
);
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});
mongoose.pluralize(null);
mongoose.connect(
  "mongodb+srv://anupbute:anupbute1@secrets.2pflmb5.mongodb.net/?retryWrites=true&w=majority&appName=secrets2"
);

let user = mongoose.Schema({
  username: String,
  email: String,
  pass: String,
});

let sec = mongoose.Schema({
  sec: String,
  email: String,
});

let new_user = mongoose.model("User", user);
let new_sec = mongoose.model("Sec", sec);

app.get("/", (req, res) => {
  res.render("intro");
});

app.get("/login", (req, res) => {
  res.render("login");
});  

app.post("/login", async (req, res) => {
  const { email, pass } = req.body;
  const user = await new_user.findOne({ email });

  if (!user || !(await bcrypt.compare(pass, user.pass))) {
    let how=1; 
    return res.render("login", {how});
  }

  req.session.user = { email: user.email, username: user.username };
  res.redirect(`/home/${user.email}`);
});

app.get("/reg", (req, res) => {
  res.render("reg");
});

app.post("/reg", async (req, res) => {
  let { username, email, pass, cnfpass } = req.body;
  let salt = await bcrypt.genSalt(10);
  let hash = await bcrypt.hash(pass, salt);
  let ak = await new_user.create({ username, email, pass: hash });
  let bk = await new_sec.create({ sec: "null", email });
  res.redirect("/login");
});

app.get("/sec", (req, res) => {
  let mail = req.query.q;
  res.render("sec", { mail });
});

app.post("/sec/:mail", async (req, res) => {
  let mail = req.params.mail;
  let ak = await new_sec.findOneAndUpdate(
    { email: mail },
    { sec: req.body.sec }
  );
  res.redirect(`/home/${mail}`);
});

app.get(
  "/home/:mail",
  (req, res, next) => {
    if (!req.session.user) {
      return res.redirect("/login");
    }
    next();
  },
  async (req, res) => {
    const { mail } = req.params;
    const sec = await new_sec.findOne({ email: mail });
    res.render("home", { sec });
  }
);

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Failed to log out");
    }
    res.redirect("/login");
  });
});

app.listen(4040);
