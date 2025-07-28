const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

const PORT = 3000;

const db = mysql.createConnection({
    host: 'rdksq2.h.filess.io',
    user: 'Team2CA2_swimmingbe',
    password: '5a49db4b01b0fd0a8023c3da5e90007105eed760',
    database: 'Team2CA2_swimmingbe',
    port: 3307,
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

function canEditToy(req, res, next) {
    const toyId = req.params.id;
    const userId = req.session.user.id;
    const userRole = req.session.user.role;
    
    if (userRole === 'admin') {
        return next();
    }

    if (userRole === 'admin') {
        return next();
    }
    
    return res.status(403).send('Access denied - Only admins can edit toys');
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

app.get('/dashboard', isLoggedIn, (req, res) => {
    console.log('User role:', req.session.user.role);
    if (req.session.user.role === 'admin') {
        res.redirect('/admin');
    } else {
        res.render('dashboard', { user: req.session.user });
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const normalizedRole = role === 'customer' ? 'user' : role;
    
    db.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', 
        [username, email, hashed, normalizedRole], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Registration failed');
        }
        res.redirect('/login');
    });
});

app.get('/toys', isLoggedIn, (req, res) => {
    db.query('SELECT * FROM toys', (err, toys) => {
        if (err) throw err;
        res.render('toys/index', { toys, user: req.session.user });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/admin', isLoggedIn, isAdmin, (req, res) => {
    db.query('SELECT * FROM users', (err, users) => {
        if (err) throw err;
        db.query('SELECT * FROM toys', (err, toys) => {
            if (err) throw err;
            res.render('admin/dashboard', { 
                users, 
                toys,
                user: req.session.user 
            });
        });
    });
});

app.get('/toys/new', isLoggedIn, (req, res) => {
    res.render('toys/new', { user: req.session.user });
});

app.post('/toys', isLoggedIn, (req, res) => {
    const { name, category, price, description } = req.body;

    if (!name || !category || !price || !description) {
        return res.status(400).send('All fields are required');
    }
    
    if (isNaN(price) || price < 0) {
        return res.status(400).send('Price must be a valid positive number');
    }
    
    const validCategories = ['Action Figures', 'Building Sets', 'Dolls', 'Educational', 'Outdoor'];
    if (!validCategories.includes(category)) {
        return res.status(400).send(`Invalid category. Please select from: ${validCategories.join(', ')}`);
    }
   
    db.query(
        'INSERT INTO toys (ProductName, Quantity, Price, Description) VALUES (?, ?, ?, ?)',
        [name, 1, parseFloat(price), description],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/toys');
        }
    );
});

app.get('/toys/:id/edit', isLoggedIn, canEditToy, (req, res) => {
    db.query('SELECT * FROM toys WHERE ProductID = ?', [req.params.id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        if (results.length === 0) {
            return res.status(404).send('Toy not found');
        }
        res.render('toys/edit', { toy: results[0], user: req.session.user });
    });
});

app.post('/toys/:id', isLoggedIn, canEditToy, (req, res) => {
    const { name, category, price, description } = req.body;
    if (!name || !category || !price || !description) {
        return res.status(400).send('All fields are required');
    }
    
    if (isNaN(price) || price < 0) {
        return res.status(400).send('Price must be a valid positive number');
    }
    
    const validCategories = ['Action Figures', 'Building Sets', 'Dolls', 'Educational', 'Outdoor'];
    if (!validCategories.includes(category)) {
        return res.status(400).send('Invalid category');
    }

    db.query(
        'UPDATE toys SET ProductName = ?, Price = ?, Description = ? WHERE ProductID = ?',
        [name, parseFloat(price), description, req.params.id],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/toys');
        }
    );
});

app.post('/toys/:id/delete', isLoggedIn, isAdmin, (req, res) => {
    const toyId = req.params.id;
    
    db.query('DELETE FROM toys WHERE ProductID = ?', [toyId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        res.redirect('/toys');
    });
});

app.get('/toys/search', isLoggedIn, (req, res) => {
    const { q, category } = req.query;
    let query = 'SELECT * FROM toys WHERE 1=1';
    const params = [];
    
    if (q && q.trim()) {
        query += ' AND (ProductName LIKE ? OR Description LIKE ?)';
        const searchTerm = `%${q.trim()}%`;
        params.push(searchTerm, searchTerm);
    }

    db.query(query, params, (err, toys) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        res.render('toys/index', { toys, user: req.session.user });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});