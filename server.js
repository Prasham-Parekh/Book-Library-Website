const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const sqlite3 = require('sqlite3').verbose();
const http = require('http');

const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('database.db');

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const userSchema = {
  id: 'INTEGER PRIMARY KEY AUTOINCREMENT',
  username: 'TEXT',
  password: 'TEXT',
  role: 'TEXT'
};

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (${Object.entries(userSchema).map(([key, value]) => `${key} ${value}`).join(', ')})`);

  db.get('SELECT * FROM users WHERE role = "admin"', (err, row) => {
    if (!row) {
      const stmt = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
      stmt.run('admin', 'adminpassword', 'admin');
      stmt.finalize();
    }
  });
});

const guestUserSchema = {
  id: 'INTEGER PRIMARY KEY AUTOINCREMENT',
  username: 'TEXT',
  password: 'TEXT',
  role: 'TEXT'
};

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS guest_users (${Object.entries(guestUserSchema).map(([key, value]) => `${key} ${value}`).join(', ')})`);
});

passport.use(new LocalStrategy((username, password, done) => {
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) return done(err);
    if (!row) {
      db.get('SELECT * FROM guest_users WHERE username = ? AND password = ?', [username, password], (err, row) => {
        if (err) return done(err);
        if (!row) return done(null, false, { message: 'Incorrect username or password' });
        return done(null, row, { message: 'Guest login' });
      });
    }
    return done(null, row, { message: 'User login' });
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
    if (row) {
      return done(err, row);
    } else {
      db.get('SELECT * FROM guest_users WHERE id = ?', [id], (err, row) => {
        return done(err, row);
      });
    }
  });
});

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.redirect('/');
}

// Registration route
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (row) {
      return res.status(400).json({ message: 'Username is already taken' });
    }

    const stmt = db.prepare('INSERT INTO guest_users (username, password, role) VALUES (?, ?, ?)');
    stmt.run(username, password, 'guest');
    stmt.finalize();

    res.redirect('/login');
  });
});

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/views/register.html');
});

// Google Books API logic
app.get('/books', (req, res) => {
  let title = req.query.title;
  if (!title) {
    return res.status(400).json({ message: 'Please enter a book title' });
  }

  let options = {
    method: 'GET',
    hostname: 'www.googleapis.com',
    port: null,
    path: `/books/v1/volumes?q=${encodeURIComponent(title)}&maxResults=20`,
    headers: {
      'useQueryString': true
    }
  };

  let apiRequest = http.request(options, (apiResponse) => {
    let bookData = '';
    apiResponse.on('data', (chunk) => {
      bookData += chunk;
    });
    apiResponse.on('end', () => {
      res.contentType('application/json').json(JSON.parse(bookData));
    });
  });
  apiRequest.end();
});

// Static server
app.use(express.static(__dirname + '/public'));

app.get(['/index.html', '/', ''], (request, response) => {
  response.sendFile(__dirname + '/views/index.html');
});

// Routes
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/', (req, res) => {
  res.send('Welcome to the application');
});

app.get('/admin', isAdmin, (req, res) => {
  res.send('Welcome admin');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`http://localhost:3000/index.html`);
});
