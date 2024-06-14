const mysql = require('mysql');
const bcrypt = require('bcryptjs');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'dbuser',
    password: 'dbpassword',
    database: 'dbname'
});

exports.handler = async (event, context) => {
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            body: 'Method Not Allowed',
        };
    }

    const { username, old_password, new_password } = JSON.parse(event.body);

    return new Promise((resolve, reject) => {
        db.query('SELECT password_hash FROM users WHERE username = ?', [username], (error, results) => {
            if (error) {
                reject({ statusCode: 500, body: 'Database query error' });
                return;
            }

            if (results.length === 0) {
                resolve({ statusCode: 400, body: JSON.stringify({ message: 'Invalid credentials' }) });
                return;
            }

            const user = results[0];

            if (!bcrypt.compareSync(old_password, user.password_hash)) {
                resolve({ statusCode: 400, body: JSON.stringify({ message: 'Invalid credentials' }) });
                return;
            }

            const new_password_hash = bcrypt.hashSync(new_password, 10);
            db.query('UPDATE users SET password_hash = ? WHERE username = ?', [new_password_hash, username], (error, results) => {
                if (error) {
                    reject({ statusCode: 500, body: 'Database update error' });
                    return;
                }

                resolve({ statusCode: 200, body: JSON.stringify({ message: 'Password updated successfully' }) });
            });
        });
    });
};
