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
db.query('SELECT user_id FROM toys WHERE id = ?', [toyId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        
        if (results.length === 0) {
            return res.status(404).send('Toy not found');
        }
        
        if (results[0].user_id === userId) {
            return next();
        }
        
        return res.status(403).send('Access denied - You can only edit your own toys');
    });
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
    db.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hashed, role], (err) => {
        if (err) throw err;
        res.redirect('/login');
    });
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


app.get('/toys/new', isLoggedIn, isAdmin, (req, res) => {
    res.render('toys/new', { user: req.session.user });
});


app.post('/toys', isLoggedIn, isAdmin, (req, res) => {
    const {name, category, price, description } = req.body;
    db.query(
        'INSERT INTO toys (name, category, price, description ) VALUES (?, ?, ?, ?, ?)',
        [name, category, price, description],
        (err) => {
            if (err) throw err;
            res.redirect('/toys');
        }
    );
});


app.get('/toys/:id/edit', isLoggedIn, canEditToy, (req, res) => {
    db.query('SELECT * FROM toys WHERE id = ?', [req.params.id], (err, results) => {
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
    
    db.query(
        'UPDATE toys SET name = ?, category = ?, price = ?, description = ? WHERE id = ?',
        [name, category, parseFloat(price), description, req.params.id],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/toys');
        }
    );
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
        return res.status(400).send('Invalid category');
    }
    
    db.query(
        'INSERT INTO toys (name, category, price, description, user_id) VALUES (?, ?, ?, ?, ?)',
        [name, category, parseFloat(price), description, req.session.user.id],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/toys');
        }
    );
});


app.post('/toys/:id/delete', isLoggedIn, (req, res) => {
    if (req.session.user.role === 'admin') {
        db.query('DELETE FROM toys WHERE id = ?', [req.params.id], (err) => {
            if (err) throw err;
            res.redirect('/toys');
        });
    } else {
        db.query('DELETE FROM toys WHERE id = ? AND user_id = ?', 
            [req.params.id, req.session.user.id], 
            (err) => {
                if (err) throw err;
                res.redirect('/toys');
            }
        );
    }
});

app.get('/toys/search', isLoggedIn, (req, res) => {
    const { q, category } = req.query;
    let query = 'SELECT * FROM toys WHERE 1=1';
    const params = [];
    
    if (q) {
        query += ' AND (name LIKE ? OR description LIKE ?)';
        params.push(`%${q}%`, `%${q}%`);
    }
    
    if (category) {
        query += ' AND category = ?';
        params.push(category);
    }
    
    db.query(query, params, (err, toys) => {
        if (err) throw err;
        res.render('toys/index', { toys, user: req.session.user });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
