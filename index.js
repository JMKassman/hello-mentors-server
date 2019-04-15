const express = require('express');
const mysql = require('mysql')
const passport = require('passport');
const LocalStrategy = require( 'passport-local').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');
const uuid = require('uuid/v4');
const https = require('https');

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
    connection.query('SELECT * FROM users WHERE email = ?', [username], (err, rows) => {
        if (err) return done(err);
        if (rows.length !== 1) return done(null, false);
        if (rows[0].password == NULL) return done(null, false);
        bcrypt.compare(password, rows[0].password, (err, same) => {
            if (err) return done(null, false);
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

app.get('/forgot-password', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/');
        return;
    }
    res.sendFile('/usr/src/app/static/forgot-password.html');
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
    connection.query("INSERT INTO tickets (hacker_id, submit_time, status, location, tags, message) VALUES(?, NOW(), 'Open', ?, ?, ?)",
                        [req.user.id, req.body.location, req.body.tags, req.body.message],
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
                        res.json(rows);
                    });
});

app.get('/api/get-mentor-tickets', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Mentor" && req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    connection.query("SELECT tickets.id, users.name, users.email, tickets.submit_time, tickets.location, tickets.tags, tickets.message FROM tickets INNER JOIN users ON tickets.hacker_id=users.id WHERE tickets.mentor_id = ? AND tickets.status = 'Claimed' ORDER BY tickets.submit_time DESC",
                    [req.user.id],
                    (err, rows) => {
                        if (err) {
                            res.sendStatus(500);
                            return;
                        }
                        console.log(`Sending mentor's claimed tickets to ${req.user.name}`);
                        res.json(rows);
                    });
});

app.get('/api/get-hacker-tickets', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Hacker") {
        res.sendStatus(403);
        return;
    }
    connection.query("SELECT tickets.id, tickets.status, users.name, tickets.submit_time, tickets.location, tickets.tags, tickets.message FROM tickets LEFT JOIN users ON tickets.mentor_id=users.id  WHERE tickets.hacker_id = ? AND (tickets.status = 'Open' OR tickets.status = 'Claimed') ORDER BY tickets.submit_time DESC",
                    [req.user.id],
                    (err, rows) => {
                        if (err) {
                            res.sendStatus(500);
                            return;
                        }
                        console.log(`Sending hackers open/claimed tickets to ${req.user.name}`);
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

/**
 * Checks in the mentor defined by the given email
 * {
 *  email: string
 * }
 * Returns:
 * {
 *  success: boolean
 * }
 * Reasons for failure: invalid email, already checked in
 */
app.post('/api/checkin-mentor', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if(req.body.email == undefined) {
        res.sendStatus(400);
        return;
    }
    connection.query("UPDATE mentors SET status = 'In', start_time = NOW() WHERE mentor_id = (SELECT id FROM users WHERE email = ?) AND status = 'Out'",
                        [req.body.email],
                        (err, result) => {
                            if (err) {
                                console.log(err);
                                res.sendStatus(500);
                                return;
                            }
                            if (result.affectedRows === 1) {
                                res.json({success: true});
                            }
                            else {
                                res.json({success: false});
                            }
                        });
});

/**
 * Checks out the mentor defined by the given email
 * {
 *  email: string
 * }
 * Returns:
 * {
 *  success: boolean
 * }
 * Reasons for failure: invalid email, not checked in
 */
app.post('/api/checkout-mentor', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if(req.body.email == undefined) {
        res.sendStatus(400);
        return;
    }
    connection.query("UPDATE mentors SET status = 'Out', end_time = NOW(), total_time = TIMEDIFF(NOW(), start_time) WHERE mentor_id = (SELECT id FROM users WHERE email = ?) AND status = 'In'",
                        [req.body.email],
                        (err, result) => {
                            if (err) {
                                console.log(err);
                                res.sendStatus(500);
                                return;
                            }
                            if (result.affectedRows === 1) {
                                res.json({success: true});
                            }
                            else {
                                res.json({success: false});
                            }
                        });
});

app.get('/api/get-current-mentors', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    connection.query("SELECT users.name, users.email, mentors.skills, (SELECT COUNT(status) > 0 FROM tickets WHERE mentor_id = 2 AND status LIKE 'Claimed') AS status, mentors.start_time, TIMEDIFF(NOW(), mentors.start_time) AS elapsed_time FROM mentors INNER JOIN users ON mentors.mentor_id=users.id WHERE mentors.status = 'In'", (err, rows) => {
        if (err) {
            res.sendStatus(500);
            return;
        }
        res.json(rows);
    });
});

const sendgrid_options = {
    "method": "POST",
    "hostname": "api.sendgrid.com",
    "port": null,
    "path": "/v3/mail/send",
    "headers": {
      "authorization": "Bearer " + process.env.SENDGRID_API_KEY,
      "content-type": "application/json"
    }
}

app.post('/api/request-password-reset', (req, res) => {
    if (req.body.email == undefined) {
        res.sendStatus(400);
        return;
    }
    let token = uuid();
    connection.query("UPDATE users SET password_reset_token = ?, password_reset_token_expiration = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE email = ?",
                        [token, req.body.email],
                        (err, result) => {
                            if (err) {
                                res.sendStatus(500);
                                return;
                            }
                            if (result.affectedRows === 1) {
                                //valid email
                                res.sendStatus(200);
                                //get name of user
                                connection.query("SELECT name FROM users WHERE email = ?", [req.body.email], (err, rows) => {
                                    if (err) {
                                        console.log("Failed to get name for password reset. No email sent");
                                        return;
                                    }
                                    //send email
                                    let sendgrid_req = https.request(sendgrid_options, function (sendgrid_res) {
                                        var chunks = [];
                                    
                                        sendgrid_res.on("data", function (chunk) {
                                          chunks.push(chunk);
                                        });
                                    
                                        sendgrid_res.on("end", function () {
                                          var body = Buffer.concat(chunks);
                                          console.log("Response from sendgrid:");
                                          console.log(body);
                                        });
                                      });

                                    let reset_link = "https://hellomentors.jmkassman.com/reset-password?token=" + token;
                                    sendgrid_req.write(JSON.stringify({ personalizations: 
                                       [ { to: [ { email: req.body.email, name: rows[0].name } ],
                                           dynamic_template_data: 
                                            { "reset_link": reset_link} } ],
                                      from: { email: process.env.SENDGRID_FROM_ADDRESS, name: 'The Hello Mentors Team' },
                                      template_id: 'd-78494412b4964869a436b164cb32214a' }));
                                    sendgrid_req.end();
                                });
                            }
                            else {
                                //invalid email
                                res.sendStatus(200);
                            }
                        });
});

app.listen(port, () => console.log(`App is listening on port ${port}`));