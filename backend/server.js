// Tambahan atau modifikasi di backend/server.js

const express = require('express');
const mysql = require('mysql2/promise'); // Menggunakan promise agar lebih mudah dengan async/await
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const NodeRSA = require('node-rsa');
const crypto = require('crypto'); // Modul crypto bawaan Node.js untuk AES
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('frontend'));

// Konfigurasi Database (sesuaikan dengan setup Anda)
const dbConfig = {
    host: '127.0.0.1',
    user: 'root',
    password: '',
    database: 'kemjar'
};

const pool = mysql.createPool(dbConfig); // Menggunakan pool untuk manajemen koneksi

function generateRSAKeys() {
    const key = new NodeRSA({ b: 2048 }); // Ukuran kunci 2048 bit untuk keamanan
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
    // Memastikan privateKey adalah string yang valid untuk diimport
    if (typeof privateKey !== 'string' || privateKey.trim() === '') {
        throw new Error('Invalid private RSA key format.');
    }
    const key = new NodeRSA(privateKey, 'private'); // Perbaikan di sini
    return key.decrypt(encryptedAESKey, 'utf8');
}

// Fungsi utilitas untuk enkripsi AES
function encryptAES(text, keyHex) {
    if (typeof keyHex !== 'string' || keyHex.length !== 64) {
        throw new Error('Invalid AES key. Must be 64 hex characters (32 bytes).');
    }
    const iv = crypto.randomBytes(16); // Initialization Vector
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Simpan IV bersama dengan data terenkripsi
}

// Fungsi utilitas untuk dekripsi AES
function decryptAES(encryptedText, keyHex) {
    if (typeof keyHex !== 'string' || keyHex.length !== 64) {
        throw new Error('Invalid AES key. Must be 64 hex characters (32 bytes).');
    }
    const textParts = encryptedText.split(':');
    if (textParts.length !== 2) {
        throw new Error('Invalid encrypted data format. Must be IV:encryptedData.');
    }
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedData = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Middleware untuk verifikasi token JWT dan mendekripsi aes_key
// Asumsi: Token yang dikirim dari frontend adalah username, ini perlu diganti dengan JWT di produksi.
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        console.log('No token provided');
        return res.status(401).json({ message: 'Authentication token required' });
    }

    try {
        const [rows] = await pool.query('SELECT id, username, private_rsa_key, aes_key FROM users WHERE username = ?', [token]);
        
        if (rows.length === 0) {
            console.log('User not found for token:', token);
            return res.status(403).json({ message: 'Invalid token' });
        }

        const user = rows[0];

        // *** PERBAIKAN UTAMA DI SINI ***
        // Langsung inisialisasi NodeRSA dengan kunci privat
        let rsaKey;
        try {
            rsaKey = new NodeRSA(user.private_rsa_key, 'private');
        } catch (rsaError) {
            console.error('Failed to initialize NodeRSA with private key:', rsaError);
            return res.status(500).json({ message: 'Server error: Invalid RSA key format stored.' });
        }
        // *******************************


        // aes_key yang tersimpan di database adalah RSA-enkripsi dari aes_key asli.
        // Kita perlu mendekripsinya menggunakan private_rsa_key.
        let decryptedAesKey;
        try {
            decryptedAesKey = rsaKey.decrypt(user.aes_key, 'utf8'); // aes_key yang didekripsi (dalam bentuk hex)
        } catch (decryptError) {
            console.error('Failed to decrypt AES key with private RSA key:', decryptError);
            return res.status(403).json({ message: 'Authentication failed: Could not decrypt AES key.' });
        }


        req.user = {
            id: user.id,
            username: user.username,
            aesKey: decryptedAesKey // aes_key yang sudah didekripsi (dalam format hex)
        };
        next();

    } catch (error) {
        console.error('Database error or authentication failed in middleware:', error);
        res.status(500).json({ message: 'Server error during authentication' });
    }
}


// ROUTE: Pendaftaran Pengguna
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        // Periksa apakah username sudah ada
        const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds 10

        // Generate kunci RSA baru untuk pengguna
        const { publicKey, privateKey } = generateRSAKeys();

        // Generate kunci AES baru (akan digunakan untuk enkripsi data sensitif)
        const aesKey = crypto.randomBytes(32).toString('hex'); // 256-bit AES key

        // Enkripsi AES key dengan public RSA key pengguna
        const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);

        // Simpan user baru dengan hashedPassword, publicKey, privateKey, dan encryptedAesKey
        const [result] = await pool.query(
            'INSERT INTO users (username, password, aes_key, private_rsa_key) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, encryptedAESKey, privateKey]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// ROUTE: Login Pengguna
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const [rows] = await pool.query('SELECT id, username, password, aes_key, private_rsa_key FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = rows[0];

        // Bandingkan password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Dekripsi aes_key di backend menggunakan private_rsa_key yang disimpan di DB
        // CATATAN PENTING: Dalam aplikasi yang sangat aman, private_rsa_key TIDAK PERNAH boleh meninggalkan klien (browser).
        // Klien harus bertanggung jawab untuk mendekripsi aes_key dan mengirimkannya ke backend.
        let decryptedAesKey;
        try {
            decryptedAesKey = decryptAESKeyWithRSA(user.aes_key, user.private_rsa_key);
        } catch (decryptError) {
            console.error('Error decrypting AES key during login:', decryptError);
            return res.status(500).json({ message: 'Login failed: Could not decrypt user AES key.' });
        }


        // Berikan token sederhana (misalnya username) dan aes_key yang didekripsi untuk frontend
        // Di aplikasi nyata, gunakan JWT untuk token sesi
        res.status(200).json({
            message: 'Login successful',
            token: user.username, // Ganti dengan JWT di produksi!
            user_id: user.id,
            decrypted_aes_key: decryptedAesKey // Kirim AES key yang sudah didekripsi ke frontend
        });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// ROUTE: Mengambil data profil pengguna, termasuk AES key
app.get('/api/profile', authenticateToken, async (req, res) => {
    // aesKey sudah tersedia di req.user dari middleware authenticateToken
    const { username, aesKey } = req.user;

    res.status(200).json({
        username: username,
        aes_key: aesKey // Untuk tujuan pembelajaran keamanan jaringan pribadi, AES key ditampilkan
    });
});

// ROUTE: Menambah Catatan Kesehatan (Membutuhkan otentikasi)
app.post('/api/health-records', authenticateToken, async (req, res) => {
    const { record_date, record_type, details } = req.body;
    const userId = req.user.id;
    const userAesKey = req.user.aesKey;

    if (!record_date || !record_type || !details) {
        return res.status(400).json({ message: 'Record date, type, and details are required' });
    }

    try {
        // Enkripsi details menggunakan AES key milik pengguna
        const encryptedDetails = encryptAES(details, userAesKey);

        const [result] = await pool.query(
            'INSERT INTO health_records (user_id, record_date, record_type, encrypted_details) VALUES (?, ?, ?, ?)',
            [userId, record_date, record_type, encryptedDetails]
        );
        res.status(201).json({ message: 'Health record added successfully', recordId: result.insertId });

    } catch (error) {
        console.error('Error adding health record:', error);
        res.status(500).json({ message: 'Server error adding health record' });
    }
});

// ROUTE: Melihat Catatan Kesehatan (Membutuhkan otentikasi)
app.get('/api/health-records', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const userAesKey = req.user.aesKey;

    try {
        const [rows] = await pool.query(
            'SELECT id, record_date, record_type, encrypted_details, created_at FROM health_records WHERE user_id = ? ORDER BY record_date DESC',
            [userId]
        );

        // Dekripsi setiap catatan kesehatan
        const decryptedRecords = rows.map(record => {
            try {
                const decryptedDetails = decryptAES(record.encrypted_details, userAesKey);
                return {
                    id: record.id,
                    record_date: record.record_date,
                    record_type: record.record_type,
                    details: decryptedDetails,
                    created_at: record.created_at
                };
            } catch (decryptError) {
                console.error('Failed to decrypt a health record:', decryptError);
                // Jika dekripsi gagal, kembalikan data terenkripsi atau tandai sebagai error
                return {
                    id: record.id,
                    record_date: record.record_date,
                    record_type: record.record_type,
                    details: '[DECRYPTION FAILED]', // Menandai data yang gagal didekripsi
                    created_at: record.created_at,
                    error: 'Decryption failed'
                };
            }
        });

        res.status(200).json(decryptedRecords);

    } catch (error) {
        console.error('Error fetching health records:', error);
        res.status(500).json({ message: 'Server error fetching health records' });
    }
});

// Endpoint untuk menyimpan encrypted_data (tetap ada sesuai struktur awal)
app.post('/api/data', authenticateToken, async (req, res) => {
    const { data } = req.body;
    const userId = req.user.id;
    const userAesKey = req.user.aesKey; // Gunakan AES key yang sudah didekripsi

    if (!data) {
        return res.status(400).json({ message: 'Data is required' });
    }

    try {
        // Enkripsi data yang masuk menggunakan AES key pengguna
        const encryptedData = encryptAES(data, userAesKey);

        const [result] = await pool.query(
            'INSERT INTO encrypted_data (user_id, data) VALUES (?, ?)',
            [userId, encryptedData]
        );
        res.status(200).json({ message: 'Data saved successfully', id: result.insertId });
    } catch (error) {
        console.error('Error saving encrypted data:', error);
        res.status(500).json({ message: 'Error saving data' });
    }
});

// Endpoint untuk mendapatkan encrypted_data (tetap ada sesuai struktur awal)
app.post('/api/load', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const userAesKey = req.user.aesKey; // Gunakan AES key yang sudah didekripsi

    try {
        const [rows] = await pool.query(
            'SELECT id, data FROM encrypted_data WHERE user_id = ?',
            [userId]
        );

        const decryptedRows = rows.map(row => {
            try {
                const decryptedContent = decryptAES(row.data, userAesKey);
                return {
                    id: row.id,
                    data: decryptedContent // Data sudah didekripsi
                };
            } catch (decryptError) {
                console.error('Failed to decrypt data for row:', row.id, decryptError);
                return {
                    id: row.id,
                    data: '[DECRYPTION FAILED]', // Tandai jika gagal didekripsi
                    error: 'Decryption failed'
                };
            }
        });

        res.status(200).json(decryptedRows);
    } catch (error) {
        console.error('Error fetching encrypted data:', error);
        res.status(500).json({ message: 'Error fetching data' });
    }
});

app.put('/api/data/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { data } = req.body; // aesKey seharusnya sudah ada di req.user dari middleware
    const userAesKey = req.user.aesKey;

    try {
        const encrypted = encryptAES(data, userAesKey);
        await pool.query('UPDATE encrypted_data SET data = ? WHERE id = ?', [encrypted, id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Update error:', err);
        res.status(500).send('Error updating data');
    }
});

app.delete('/api/data/:id', async (req, res) => { // Perlu middleware authenticateToken juga
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM encrypted_data WHERE id = ?', [id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).send('Error deleting data');
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});