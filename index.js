const express = require('express');
const mysql = require('mysql')
const passport = require('passport');
const LocalStrategy = require( 'passport-local').Strategy;
const session = require('express-session');
const bodyParser = require('body-parser');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');
const https = require('https');
const base64url = require('base64url');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const connection_info = {
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
};

const sessionStore = new MySQLStore({
    host: process.env.MYSQL_HOST,
    port: 3306,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: "sessions"
});



//taken from https://stackoverflow.com/questions/37385833/node-js-mysql-database-disconnect
var connection;
var db_connected = false;
function handleDisconnect() {
    connection = mysql.createConnection(connection_info);  // Recreate the connection, since the old one cannot be reused.
    connection.connect( function onConnect(err) {   // The server is either down
        if (err) {                                  // or restarting (takes a while sometimes).
            console.log('error when connecting to db:', err);
            db_connected = false;
            setTimeout(handleDisconnect, 10000);    // We introduce a delay before attempting to reconnect,
        }
        else {
            db_connected = true;
        }                                           // to avoid a hot loop, and to allow our node script to
    });                                             // process asynchronous requests in the meantime.
                                                    // If you're also serving http, display a 503 error.
    connection.on('error', function onError(err) {
        console.log('db error', err);
        db_connected = false;
        if (err.code == 'PROTOCOL_CONNECTION_LOST') {   // Connection to the MySQL server is usually
            handleDisconnect();                         // lost due to either server restart, or a
        } else {                                        // connnection idle timeout (the wait_timeout
            throw err;                                  // server variable configures this)
        }
    });
}
handleDisconnect();

passport.use(new LocalStrategy((username, password, done) => {
    connection.query('SELECT * FROM users WHERE email = ?', [username], (err, rows) => {
        if (err) return done(err);
        if (rows.length !== 1) return done(null, false);
        if (rows[0].password == null) return done(null, false);
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
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
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

app.get('/reset-password', (req, res) => {
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    if (req.query.token == undefined) {
        // send bad token page
        res.sendStatus(400);
        return;
    }
    let hashed_token = crypto.createHash('sha256').update(req.query.token).digest('hex');
    connection.query("SELECT * FROM users WHERE password_reset_token = ? AND password_reset_token_expiration > NOW()", 
        [hashed_token], 
        (err, rows) => {
            if (err) {
                res.sendStatus(500);
                return;
            }
            if (rows.length == 1) {
                res.redirect(`/change-password?token=${req.query.token}`);
                return;
            }
            if (rows.length > 1) {
                // This should never happen, invalidate all matching tokens
                connection.query("UPDATE users SET password_reset_token = NULL, password_reset_token_expiration = NULL WHERE password_reset_token = ?", [hashed_token]);
                //send error page
                res.sendStatus(400);
                return;
            }
            if (rows.length == 0) {
                //update db in case the token exists but is expired
                connection.query("UPDATE users SET password_reset_token = NULL, password_reset_token_expiration = NULL WHERE password_reset_token = ?", [hashed_token]);
                //send error page
                res.sendStatus(400);
                return;
            }
    });
});

app.get('/change-password', (req, res) => {
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    if (req.query.token == undefined) {
        // send bad token page
        res.sendStatus(400);
        return;
    }
    res.sendFile('/usr/src/app/static/reset-password.html');
});
app.post('/change-password', (req, res) => {
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    if (req.query.token == undefined) {
        // send bad token page
        console.log("undefined token");
        res.sendStatus(400);
        return;
    }
    if (req.body.password == undefined) {
        //bad request
        console.log("undefined password");
        res.sendStatus(400);
    }
    bcrypt.hash(req.body.password, 10, (err, encrypted) => {
        if (err) {
            console.log("bcrypt failed");
            res.sendStatus(500);
            return;
        }
        if (!db_connected) {
            res.sendStatus(503);
            return;
        }
        let hashed_token = crypto.createHash('sha256').update(req.query.token).digest('hex');
        connection.query("UPDATE users SET password = ?, password_reset_token = NULL, password_reset_token_expiration = NULL WHERE password_reset_token = ? AND password_reset_token_expiration > NOW()", 
            [encrypted, hashed_token], 
            (err, result) => {
                if (err) {
                    res.sendStatus(500);
                    return;
                }
                if (result.affectedRows === 0) {
                    //send invalid token page
                    console.log("db query failed to update password")
                    res.sendStatus(400);
                    return;
                }
                //send file saying that password was changed successfully and link to the login page
                res.redirect('/login');
            });
    });
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
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
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    let token = base64url(crypto.randomBytes(128));
    let hashed_token = crypto.createHash('sha256').update(token).digest('hex');
    connection.query("UPDATE users SET password_reset_token = ?, password_reset_token_expiration = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE email = ?",
                        [hashed_token, req.body.email],
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

app.get('/add-hacker', (req, res) => {
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
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    res.sendFile('/usr/src/app/static/add-hacker.html');
});

app.get('/add-mentor', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    res.sendFile('/usr/src/app/static/add-mentor.html');
});

/**
 * Adds a hacker into the database with no password
 * {
 *  name: string
 *  email: unique string
 * }
 * 
 * Returns:
 *  - 403 if not authorized to perform action
 *  - 400 if name or email is not defined
 *  - 503 if database is disconnected
 *  - 400 with body {error: "Email already in use"} if Email is already in use
 *  - 500 for any other database errors
 *  - 200 if account is created successfully
 */
app.post('/api/add-hacker', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if (req.body.name == undefined || req.body.email == undefined) {
        res.sendStatus(400);
    }
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    connection.query("INSERT INTO users (name, email, role) VALUES(?, ?, 'HACKER')", [req.body.name, req.body.email], (err, result) => {
        if ( err && err.errno === 1062) {
            //email already in use
            res.status(400).json({error: "Email already in use"});
            return;
        }
        if (err) {
            console.log(err);
            res.sendStatus(500);
            return;
        }
        console.log(`Created hacker account for ${req.body.email}`);
        res.sendStatus(200);
    });
});

/**
 * Adds a mentor into the database with no password and the given tags (skills)
 * {
 *  name: string
 *  email: unique string
 *  tags: string
 * }
 * 
 * Returns:
 *  - 403 if not authorized to perform action
 *  - 400 if name or email is not defined
 *  - 503 if database is disconnected
 *  - 400 with body {error: "Email already in use"} if Email is already in use
 *  - 500 for any other database errors
 *  - 200 if account is created successfully
 */
app.post('/api/add-mentor', (req, res) => {
    if (!req.isAuthenticated()) {
        res.sendStatus(403);
        return;
    }
    if (req.user.role !== "Organizer") {
        res.sendStatus(403);
        return;
    }
    if (!db_connected) {
        res.sendStatus(503);
        return;
    }
    connection.query('CALL insert_mentor(?, ?, ?)', [req.body.name, req.body.email, req.body.tags], (err, result) => {
        if ( err && err.errno === 1062) {
            //email already in use
            res.status(400).json({error: "Email already in use"});
            return;
        }
        if (err) {
            console.log(err);
            res.sendStatus(500);
            return;
        }
        console.log(`Created mentor account for ${req.body.email}`);
        res.sendStatus(200);
    });
});

app.listen(port, () => console.log(`App is listening on port ${port}`));