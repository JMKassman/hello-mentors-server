import express from 'express';
import { createConnection } from 'mysql';
const app = express();
const port = process.env.PORT || 3000;

const connection = createConnection({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
});

connection.connect();

connection.query(' SELECT 1 + 1 AS solution', (err, rows, fields) => {
    if (err) throw err;
    console.log('The solution is: ', rows[0].solution);
});

connection.query('SELECT * FROM users', (err, rows, fields) => {
    if (err) throw err;
    console.log(rows[0].name);
});

app.get('/', (req, res) => res.send("Hello Worlds!"));

app.listen(port, () => console.log(`App is listening on port ${port}`));