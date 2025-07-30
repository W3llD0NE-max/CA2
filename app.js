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
    connectionLimit: 10
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

function getCartItemCount(cart) {
    if (!cart || !Array.isArray(cart)) return 0;
    return cart.reduce((total, item) => total + (item.quantity || 0), 0);
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
            req.session.user = { username: results[0].username, email: results[0].email, role: results[0].role };
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
        const cartItemCount = getCartItemCount(req.session.cart);
        res.render('dashboard', { 
            user: req.session.user,
            cartItemCount: cartItemCount
        });
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
        const cartItemCount = getCartItemCount(req.session.cart);
        res.render('toys/index', { 
            toys, 
            user: req.session.user,
            cartItemCount: cartItemCount
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
        const cartItemCount = getCartItemCount(req.session.cart);
        res.render('toys/index', { 
            toys, 
            user: req.session.user,
            cartItemCount: cartItemCount
        });
    });
});

app.get('/toys/new', isLoggedIn, isAdmin, (req, res) => {
    res.render('toys/new', { user: req.session.user });
});

app.get('/toys/:id', isLoggedIn, (req, res) => {
    db.query('SELECT * FROM toys WHERE ProductID = ?', [req.params.id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        if (results.length === 0) {
            return res.status(404).send('Toy not found');
        }
        const cartItemCount = getCartItemCount(req.session.cart);
        res.render('toys/show', { 
            toy: results[0], 
            user: req.session.user,
            cartItemCount: cartItemCount
        });
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

app.get('/favorites', isLoggedIn, (req, res) => {
    const favorites = req.session.favorites || [];
    if (favorites.length === 0) {
        return res.render('favorites', { 
            toys: [], 
            user: req.session.user,
            cartItemCount: getCartItemCount(req.session.cart)
        });
    }
    
    const placeholders = favorites.map(() => '?').join(',');
    db.query(`SELECT * FROM toys WHERE ProductID IN (${placeholders})`, favorites, (err, toys) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        const cartItemCount = getCartItemCount(req.session.cart);
        res.render('favorites', { 
            toys, 
            user: req.session.user,
            cartItemCount: cartItemCount
        });
    });
});

app.post('/favorites/add/:id', isLoggedIn, (req, res) => {
    const toyId = parseInt(req.params.id);
    if (!req.session.favorites) {
        req.session.favorites = [];
    }
    
    if (!req.session.favorites.includes(toyId)) {
        req.session.favorites.push(toyId);
    }
    
    res.json({ success: true, message: 'Added to favorites' });
});

app.post('/favorites/remove/:id', isLoggedIn, (req, res) => {
    const toyId = parseInt(req.params.id);
    if (req.session.favorites) {
        req.session.favorites = req.session.favorites.filter(id => id !== toyId);
    }
    
    res.json({ success: true, message: 'Removed from favorites' });
});


app.get('/users/:username/edit', isLoggedIn, isAdmin, (req, res) => {
    const username = req.params.username;
    
    
    if (username === req.session.user.username) {
        return res.status(403).send('You cannot edit your own account');
    }
    
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.render('admin/edit-user', { editUser: results[0], user: req.session.user });
    });
});

app.post('/users/:username', isLoggedIn, isAdmin, async (req, res) => {
    const username = req.params.username;
    const { username: newUsername, email, role, password } = req.body;
    
    // Prevent editing own account
    if (username === req.session.user.username) {
        return res.status(403).send('You cannot edit your own account');
    }
    
    if (!newUsername || !email || !role) {
        return res.status(400).send('Username, email, and role are required');
    }
    
    const validRoles = ['admin', 'user'];
    if (!validRoles.includes(role)) {
        return res.status(400).send('Invalid role');
    }
    
    try {
        let updateQuery = 'UPDATE users SET username = ?, email = ?, role = ?';
        let queryParams = [newUsername, email, role];
        
        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', password = ?';
            queryParams.push(hashedPassword);
        }
        
        updateQuery += ' WHERE username = ?';
        queryParams.push(username);
        
        db.query(updateQuery, queryParams, (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Database error');
            }
            res.redirect('/admin');
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.post('/users/:username/delete', isLoggedIn, isAdmin, (req, res) => {
    const username = req.params.username;
    
    // Prevent deleting own account
    if (username === req.session.user.username) {
        return res.status(403).send('You cannot delete your own account');
    }
    
    db.query('DELETE FROM users WHERE username = ?', [username], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }
        res.redirect('/admin');
    });
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

app.post('/add-to-cart/:id', isLoggedIn, (req, res) => {
    const productId = parseInt(req.params.id);
    const quantity = parseInt(req.body.quantity) || 1;
 
    if (isNaN(productId) || productId <= 0 || isNaN(quantity) || quantity <= 0) {
        return res.status(400).send('Invalid product ID or quantity.');
    }
 
    db.query('SELECT * FROM toys WHERE ProductID = ?', [productId], (error, results) => {
        if (error) {
            console.error('Error fetching product for cart:', error);
            return res.status(500).send('An error occurred while adding to cart.');
        }
 
        if (results.length > 0) {
            const product = results[0];
 
            if (!req.session.cart) {
                req.session.cart = [];
            }
 
            const existingItem = req.session.cart.find(item => item.productId === productId);
            if (existingItem) {
                existingItem.quantity += quantity;
            } else {
                req.session.cart.push({
                    productId: product.ProductID,
                    productName: product.ProductName,
                    price: product.Price,
                    quantity: quantity,
                    image: product.Image
                });
            }
 
            res.redirect('/cart');
        } else {
            res.status(404).send("Product not found.");
        }
    });
});
 
app.post('/remove-from-cart/:id', isLoggedIn, (req, res) => {
    const productIdToRemove = parseInt(req.params.id);
 
    if (!req.session.cart) {
        return res.redirect('/cart');
    }
 
    req.session.cart = req.session.cart.filter(item => item.productId !== productIdToRemove);
    res.redirect('/cart');
});
 
app.post('/update-cart-quantity/:id', isLoggedIn, (req, res) => {
    const productIdToUpdate = parseInt(req.params.id);
    const newQuantity = parseInt(req.body.quantity);
 
    if (isNaN(newQuantity) || newQuantity < 1) {
        return res.status(400).send('Quantity must be a positive number.');
    }
 
    if (!req.session.cart) {
        return res.redirect('/cart');
    }
 
    const itemToUpdate = req.session.cart.find(item => item.productId === productIdToUpdate);
 
    if (itemToUpdate) {
        itemToUpdate.quantity = newQuantity;
    }
    res.redirect('/cart');
});
 
app.get('/cart', isLoggedIn, (req, res) => {
    const cart = req.session.cart || [];
    const cartItemCount = getCartItemCount(cart);
    res.render('cart', { 
        cart, 
        user: req.session.user,
        cartItemCount: cartItemCount
    });
});
 
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
