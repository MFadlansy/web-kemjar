const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'kemjar',
});

function generateRSAKeys() {
    const key = new NodeRSA({ b: 2048 });
    return {
        publicKey: key.exportKey('public'),
        privateKey: key.exportKey('private')
    };
}
function encryptAESKeyWithRSA(aesKey, publicKey) {
    const key = new NodeRSA(publicKey);
    return key.encrypt(aesKey, 'base64');
}

function decryptAESKeyWithRSA(encryptedAESKey, privateKey) {
    const key = new NodeRSA(privateKey);
    return key.decrypt(encryptedAESKey, 'utf8');
}

function encryptAES(data, key) {
    if (typeof key !== 'string' || key.length !== 64) {
        throw new Error('Invalid AES key. Must be 64 hex characters (32 bytes).');
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptAES(encrypted, key) {
    const [ivHex, dataHex] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(dataHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);

        const { publicKey, privateKey } = generateRSAKeys();

        const aesKey = crypto.randomBytes(32).toString('hex'); // 32 bytes → 64 hex chars

        const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

        await pool.query('INSERT INTO users (username, password, aes_key, private_rsa_key) VALUES (?, ?, ?, ?)', [
            username, 
            hashed, 
            encryptedAESKey, 
            privateKey
        ]);

        res.sendStatus(200);
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).send('Register failed');
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).send('Invalid username');
        
        const match = await bcrypt.compare(password, rows[0].password);
        if (!match) return res.status(401).send('Invalid password');
        
        // Decrypt AES key with the user's private RSA key
        const aesKey = decryptAESKeyWithRSA(rows[0].aes_key, rows[0].private_rsa_key);

        res.json({ userId: rows[0].id, aesKey });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Login failed');
    }
});

app.post('/api/data', async (req, res) => {
    const { userId, data, aesKey } = req.body;
    try {
        const encrypted = encryptAES(data, aesKey);
        await pool.query('INSERT INTO encrypted_data (user_id, data) VALUES (?, ?)', [userId, encrypted]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Save error:', err);
        res.status(500).send('Error saving data');
    }
});

app.post('/api/load', async (req, res) => {
    const { userId, aesKey } = req.body;
    try {
        const [rows] = await pool.query('SELECT id, data FROM encrypted_data WHERE user_id = ?', [userId]);
        const decrypted = rows.map(row => ({
            id: row.id,
            data: decryptAES(row.data, aesKey)
        }));
        res.json(decrypted);
    } catch (err) {
        console.error('Load error:', err);
        res.status(500).send('Error loading data');
    }
});

app.put('/api/data/:id', async (req, res) => {
    const { id } = req.params;
    const { data, aesKey } = req.body;
    try {
        const encrypted = encryptAES(data, aesKey);
        await pool.query('UPDATE encrypted_data SET data = ? WHERE id = ?', [encrypted, id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Update error:', err);
        res.status(500).send('Error updating data');
    }
});

app.delete('/api/data/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM encrypted_data WHERE id = ?', [id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).send('Error deleting data');
    }
});


app.listen(3000, () => console.log('Server running on http://localhost:3000'));
