
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('./database/shiftlog.db');

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'shiftlogsecret',
  resave: false,
  saveUninitialized: true
}));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee TEXT,
  shift TEXT,
  machine TEXT,
  work_done TEXT,
  issues TEXT,
  actions TEXT,
  suggestions TEXT,
  remarks TEXT,
  status TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

const admin = db.prepare("SELECT * FROM users WHERE email=?").get("admin@company.com");
if (!admin) {
  const hash = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (email,password,role) VALUES (?,?,?)")
    .run("admin@company.com", hash, "Admin");
}

function requireLogin(req,res,next){
  if(!req.session.user) return res.redirect('/');
  next();
}

app.get('/', (req,res)=> res.render('login'));

app.post('/login',(req,res)=>{
  const { email,password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(user && bcrypt.compareSync(password,user.password)){
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    res.send("Invalid credentials");
  }
});

app.get('/dashboard',requireLogin,(req,res)=>{
  const logs = db.prepare("SELECT * FROM logs ORDER BY created_at DESC").all();
  res.render('dashboard',{user:req.session.user,logs});
});

app.post('/add-log',requireLogin,(req,res)=>{
  const {shift,machine,work_done,issues,actions,suggestions,remarks,status} = req.body;
  db.prepare(`INSERT INTO logs 
  (employee,shift,machine,work_done,issues,actions,suggestions,remarks,status)
  VALUES (?,?,?,?,?,?,?,?,?)`)
  .run(req.session.user.email,shift,machine,work_done,issues,actions,suggestions,remarks,status);
  res.redirect('/dashboard');
});

app.get('/logout',(req,res)=>{
  req.session.destroy(()=> res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=> console.log("Server running on port "+PORT));
