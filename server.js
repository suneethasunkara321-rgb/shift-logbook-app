
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'shiftlogsecret',
  resave: false,
  saveUninitialized: false
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user.role !== 'Admin') return res.send("Access Denied");
  next();
}

app.get('/', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    res.send("Invalid credentials");
  }
});

app.get('/dashboard', requireLogin, async (req, res) => {
  let logs;

  if (req.session.user.role === 'Employee') {
    logs = await pool.query(
      'SELECT * FROM logs WHERE employee=$1 ORDER BY created_at DESC',
      [req.session.user.email]
    );
  } else {
    logs = await pool.query('SELECT * FROM logs ORDER BY created_at DESC');
  }

  res.render('dashboard', { user: req.session.user, logs: logs.rows });
});

app.post('/add-log', requireLogin, async (req, res) => {
  const { shift, machine, work_done, issues, actions, suggestions, remarks, status } = req.body;

  await pool.query(
    `INSERT INTO logs 
    (employee, shift, machine, work_done, issues, actions, suggestions, remarks, status)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      req.session.user.email,
      shift,
      machine,
      work_done,
      issues,
      actions,
      suggestions,
      remarks,
      status
    ]
  );

  res.redirect('/dashboard');
});

// Admin Panel
app.get('/users', requireLogin, requireAdmin, async (req, res) => {
  const users = await pool.query('SELECT id, email, role FROM users ORDER BY id ASC');
  res.render('users', { users: users.rows });
});

app.post('/add-user', requireLogin, requireAdmin, async (req, res) => {
  const { email, role } = req.body;
  const defaultPassword = bcrypt.hashSync("123456", 10);

  await pool.query(
    'INSERT INTO users (email, password, role) VALUES ($1,$2,$3)',
    [email, defaultPassword, role]
  );

  res.redirect('/users');
});

app.post('/delete-user/:id', requireLogin, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
  res.redirect('/users');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
