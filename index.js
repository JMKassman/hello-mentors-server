const express = require('express');
const mysql = require('mysql');
const app = express();
const port = process.env.PORT || 3000;

const connection = mysql.createConnection({
    host: 'mysql',
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
});

connection.connect();

connection.query(' SELECT 1 + 1 AS solution', (err, rows, fields) => {
    if (err) throw err;
    console.log('The solution is: ', rows[0].solution);
});

app.get('/', (req, res) => res.send("Hello World!"));

app.listen(port, () => console.log(`App is listening on port ${port}`));