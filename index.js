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
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("/usr/src/app/static"));

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

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/');
        return;
    }
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

/**
 * Creates a new ticket in the system defined by JSON or application/x-www-form-urlencoded
 * {
 *  location: "string",
 *  tags: "string", //format: 'tag1,tag2,...'
 *  message: "string"
 * }
 */
app.post('/api/submit-ticket', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.body.location == undefined || req.body.tags == undefined || req.body.message == undefined) {
        res.sendStatus(400);
        return;
    }
    let time = new Date();
    let timeString = `${time.getFullYear()}-${time.getMonth()+1}-${time.getDate()} ${time.getHours()}:${time.getMinutes()}:${time.getSeconds()}`;
    connection.query("INSERT INTO tickets (hacker_id, submit_time, status, location, tags, message) VALUES(?, ?, 'Open', ?, ?, ?)",
                        [req.user.id, timeString, req.body.location, req.body.tags, req.body.message],
                        (err, result) => {
                            if (err) {
                                res.sendStatus(500);
                                return;
                            }
                            if (result.affectedRows === 1) {
                                res.sendStatus(201);
                                return;
                            }
                            res.sendStatus(400);
                        });
});

app.get('/api/get-open-tickets', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    connection.query("SELECT tickets.id, users.name, users.email, tickets.submit_time, tickets.location, tickets.tags, tickets.message FROM tickets INNER JOIN users ON tickets.hacker_id=users.id WHERE tickets.status = 'Open' ORDER BY tickets.submit_time ASC", 
                    (err, rows) => {
                        if (err) {
                            res.sendStatus(500);
                            return;
                        }
                        console.log(`Sending open tickets to ${req.user.name}`);
                        console.log(rows);
                        res.json(rows);
                    });
});

app.get('/api/get-all-tickets', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    connection.query("SELECT tickets.id, users.name, users.email, tickets.submit_time, tickets.location, tickets.tags, tickets.message, tickets.status FROM tickets INNER JOIN users ON tickets.hacker_id=users.id ORDER BY tickets.submit_time ASC", 
                    (err, rows) => {
                        if (err) {
                            res.sendStatus(500);
                            return;
                        }
                        console.log(`Sending all tickets to ${req.user.name}`);
                        console.log(rows);
                        res.json(rows);
                    });
});

/**
 * Assigns the requesting user to the ticket if it is unclaimed
 * {
 *  id: integer
 * }
 */
app.post('/api/claim-ticket', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if(req.body.id == undefined) {
        res.sendStatus(400);
        return;
    }
    connection.query("UPDATE tickets SET mentor_id = ?, status = 'Claimed' WHERE mentor_id IS NULL AND id = ?", [req.user.id, req.body.id], (err, result) => {
        if (err) {
            res.sendStatus(500);
            return;
        }
        if (result.affectedRows === 1) {
            res.json({claimed: true});
        }
        else {
            res.json({claimed: false});
        }
    });
});

/**
 * Removes the requesting user from the ticket if it is claimed by them
 * {
 *  id: integer
 * }
 */
app.post('/api/unclaim-ticket', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if(req.body.id == undefined) {
        res.sendStatus(400);
        return;
    }
    connection.query("UPDATE tickets SET mentor_id = NULL, status = 'Open' WHERE mentor_id = ? AND id = ? AND status = 'Claimed'", [req.user.id, req.body.id], (err, result) => {
        if (err) {
            res.sendStatus(500);
            return;
        }
        if (result.affectedRows === 1) {
            res.json({unclaimed: true});
        }
        else {
            res.json({unclaimed: false});
        }
    });
});

/**
 * Closes the requesting user's claimed ticket if it is claimed by them
 * {
 *  id: integer
 * }
 */
app.post('/api/close-ticket', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if(req.body.id == undefined) {
        res.sendStatus(400);
        return;
    }
    connection.query("UPDATE tickets SET status = 'Closed' WHERE mentor_id = ? AND id = ? AND status = 'Claimed'", [req.user.id, req.body.id], (err, result) => {
        if (err) {
            res.sendStatus(500);
            return;
        }
        if (result.affectedRows === 1) {
            res.json({unclaimed: true});
        }
        else {
            res.json({unclaimed: false});
        }
    });
});

app.listen(port, () => console.log(`App is listening on port ${port}`));