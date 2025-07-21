const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

const PORT = 3000;

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'toystore_db'
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL Connected');
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'supersecretkey',
    resave: false,
    saveUninitialized: false
}));

function isLoggedIn(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).send('Access denied');
}

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length > 0 && await bcrypt.compare(password, results[0].password)) {
            req.session.user = { id: results[0].id, role: results[0].role };
            res.redirect('/dashboard');
        } else {
            res.send('Login failed');
        }
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hashed, role], (err) => {
        if (err) throw err;
        res.redirect('/login');
    });
});

app.get('/dashboard', isLoggedIn, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});

app.get('/toys', isLoggedIn, (req, res) => {
    db.query('SELECT * FROM toys', (err, toys) => {
        if (err) throw err;
        res.render('toys/index', { toys });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
