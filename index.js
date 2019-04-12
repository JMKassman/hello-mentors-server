const express = require('express');
const mysql = require('mysql')
const passport = require('passport');
const LocalStrategy = require( 'passport-local').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

const connection = mysql.createConnection({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
});

const sessionStore = new MySQLStore({
    host: process.env.MYSQL_HOST,
    port: 3306,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: "sessions"
});

connection.connect();

passport.use(new LocalStrategy((username, password, done) => {
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, rows) => {
        if (err) return done(err);
        if (rows.length !== 1) return done(null, false);
        bcrypt.compare(password, rows[0].password, (err, same) => {
            return same ? done(null, rows[0]) : done(null, false);
        });
    });
}));

passport.serializeUser((user, done) => {
    return done(null, user.id);
});

passport.deserializeUser((id, done) => {
    connection.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
        if (err) done(err);
        return done(null, rows[0]);
    });
});

app.use(session({ store: sessionStore, secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("/usr/src/app/static"));

app.get('/login', (req, res) => {
    res.sendFile('/usr/src/app/static/login.html');
});
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        req.login(user, (err) => {
            if (err) {
                return res.redirect('/login?err');
            }
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
  });

app.get('/hello', (req, res) => {
    res.send("Hello World!")
});

app.get('/hacker', (req,res) => {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
        return;
    }
    if (req.user.role !== "Hacker" && req.user.role !== "Organizer") {
        res.redirect('/');
        return;
    }
    res.sendFile('/usr/src/app/static/hacker.html');
});

app.get('/mentor', (req, res) => {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.redirect('/');
        return;
    }
    res.sendFile('/usr/src/app/static/mentor.html');
});

app.get('/organizer', (req, res) => {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
        return;
    }
    if (req.user.role !== "Organizer") {
        res.redirect('/');
        return;
    }
    res.sendFile('/usr/src/app/static/organizer.html');
});

app.get('/', (req, res) => {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
        return;
    }
    if (req.user.role === 'Hacker') {
        console.log("GET / Redirecting to /hacker");
        res.redirect('/hacker');
        return;
    }
    if (req.user.role === 'Mentor') {
        res.redirect('/mentor');
        return;
    }
    if (req.user.role === 'Organizer') {
        res.redirect('/organizer');
        return;
    }
    res.send('You are now authenticated as ' + req.user.name);
});

app.listen(port, () => console.log(`App is listening on port ${port}`));