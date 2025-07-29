const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const app = express();

const PORT = 3000;

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'toy-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 
    },
    fileFilter: function (req, file, cb) {

        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

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
    const userRole = req.session.user.role;
    
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
            res.render('login-fail'); 
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

app.get('/toys/new', isLoggedIn, isAdmin, (req, res) => {
    res.render('toys/new', { user: req.session.user });
});

app.post('/toys', isLoggedIn, isAdmin, upload.single('image'), (req, res) => {
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

    const imagePath = req.file ? req.file.filename : '';

    db.query(
        'INSERT INTO toys (ProductName, Quantity, Price, Description, Image) VALUES (?, ?, ?, ?, ?)',
        [name, 1, parseFloat(price), description, imagePath],
        (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/admin');
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

app.post('/toys/:id', isLoggedIn, canEditToy, upload.single('image'), (req, res) => {
    const { name, category, price, description, quantity } = req.body;

    if (!name || !category || !price || !description || quantity === undefined) {
        return res.status(400).send('All fields are required');
    }

    if (isNaN(price) || price < 0 || isNaN(quantity) || quantity < 0) {
        return res.status(400).send('Price and Quantity must be valid positive numbers');
    }

    const validCategories = ['Action Figures', 'Building Sets', 'Dolls', 'Educational', 'Outdoor'];
    if (!validCategories.includes(category)) {
        return res.status(400).send('Invalid category');
    }

    let updateQuery = 'UPDATE toys SET ProductName = ?, Price = ?, Description = ?, Quantity = ?';
    let queryParams = [name, parseFloat(price), description, parseInt(quantity)];

    if (req.file) {
        updateQuery += ', Image = ?';
        queryParams.push(req.file.filename);
    }

    updateQuery += ' WHERE ProductID = ?';
    queryParams.push(req.params.id);

    db.query(updateQuery, queryParams, (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        res.redirect('/admin');
    });
});


app.post('/toys/:id/delete', isLoggedIn, isAdmin, (req, res) => {
    const toyId = req.params.id;

    db.query('SELECT Image FROM toys WHERE ProductID = ?', [toyId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }

        db.query('DELETE FROM toys WHERE ProductID = ?', [toyId], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            if (results.length > 0 && results[0].Image) {
                const imagePath = path.join(__dirname, 'public', 'uploads', results[0].Image);
                fs.unlink(imagePath, (err) => {
                    if (err) console.log('Could not delete image file:', err);
                });
            }
            
            res.redirect('/admin');
        });
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