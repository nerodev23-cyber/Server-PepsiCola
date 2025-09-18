// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
 const port = 3000;



const corsOptions = {
       origin: [
    'http://localhost:3000',
    'http://127.0.0.1:5501',
    'https://web-pessico.onrender.com',
    'https://web-pessico-page2.onrender.com',  // เพิ่มตรงนี้
    'https://server-pepsicola-1.onrender.com' // อันนี้ไม่จำเป็นต้องมี
  ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
};


app.use(express.json());
///app.use(cors());
app.use(cors(corsOptions));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public'))); // บอก Express ว่า public เป็น folder ของไฟล์เว็บที่ browser สามารถเข้าถึงได้โดยตรง”


const pool = mysql.createPool({
    host: 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com', // <-- แก้เป็น Host จาก TiDB
    port: 4000, // TiDB ใช้พอร์ต 4000
    user: 'JnL6ewoYDcY1rHE.root', // Username จาก TiDB
    password: 'WlVo4iUlzoP0pPUJ', // Password จาก TiDB
    database: 'registercarinfo', // Database ของคุณ
    ssl: { rejectUnauthorized: true }, // ต้องใส่ ssl สำหรับ TiDB
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


// const pool = mysql.createPool({
//     host: 'localhost',
//     user: 'root',
//     password: '123456',
//     database: 'registercarinfo',
//     waitForConnections: true,
//     connectionLimit: 10,
//     queueLimit: 0
// });

// ตั้งค่าการเชื่อมต่อ MySQL



// =============================================== API ลงทะเบียน เก็บข้อมูล ======================================================
// Meddleware
const meddlewareRegisterUser = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 50, // จำกัด 3 ครั้งต่อ 15 นาที
    message: {
        error: 'Too many registration attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

// API Endpoint สำหรับการลงทะเบียนผู้ใช้งาน
app.post('/api/register', meddlewareRegisterUser, async (req, res) => {
    let conn;
    try {
        // ดึงข้อมูลจาก body
        const { fullName, username, password, phone, supplierName } = req.body;

        // ตรวจสอบข้อมูลที่จำเป็น
        if (!fullName || !username || !password || !phone) {
            return res.status(400).json({
                error: 'Please provide full name, username, password, and phone number.'
            });
        }

        // แฮชรหัสผ่าน
      //const hashedPassword = await bcrypt.hash(password, 10);

        conn = await pool.getConnection();

        // ตรวจสอบว่า username ซ้ำหรือไม่
        const [existingUser] = await conn.execute(
            'SELECT username FROM registrationsUser WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            return res.status(409).json({ error: ' User นี้มีข้อมูลอยู่แล้ว ' });
        }

        // ตรวจสอบในตาราง accounts ด้วย
        const [existingAccount] = await conn.execute(
            'SELECT username FROM accounts WHERE username = ?',
            [username]
        );

        if (existingAccount.length > 0) {
            return res.status(409).json({ error: 'User นี้มีข้อมูลอยู่แล้วใน accounts' });
        }


        // สร้าง query สำหรับเพิ่มข้อมูล
        const sql = `
            INSERT INTO registrationsUser (full_name, username, password_hash, phone, supplier_name)
            VALUES (?, ?, ?, ?, ?)
        `;

        const values = [
            fullName,
            username,
          //hashedPassword,
          password,
            phone,
            supplierName || null
        ];

        const [result] = await conn.execute(sql, values);

        return res.status(201).json({
            message: 'User registered successfully!',
            userId: result.insertId
        });

    } catch (error) {
        console.error('Error during user registration:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    } finally {
        if (conn) conn.release(); // ปล่อย connection เสมอ
    }
});


// =============================================== API ลงทะเบียน เก็บข้อมูล  END ======================================================




// ============================== Login Admin or User V 2  ===============================================================================

const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 นาที
    max: 3, // จำกัด 5 ครั้งต่อ 15 นาที (เข้มงวดกว่า)
    message: {
        error: 'มีการพยายามเข้าสู่ระบบมากเกินไป กรุณารอ 15 นาที'
    },
    standardHeaders: true,
    legacyHeaders: false,
});


//const activeSessions = new Map();
const sessions = {};

// Login route
app.post('/loginAdminandUser', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    
    if (!username || !password) {
        return res.status(400).json({ message: 'กรุณาใส่กรอกข้อมูล user และ password' });
    }

    try {
        const [result] = await pool.query(
            'SELECT * FROM accounts WHERE username = ? AND password_hash = ?',
            [username, password]
        );

        if (result.length === 0) {
            return res.status(401).json({ message: 'User หรือ Password ไม่ถูกต้อง' });
        }

        const user = result[0];

        // สร้าง session key
        const sessionKey = crypto.randomBytes(16).toString('hex');
        const expireTime = Date.now() + 24 * 60 * 60 * 1000; // 24 ชั่วโมง
       // const expireTime = Date.now() + 1 * 60 * 1000; //  นาที
        //const expireTime = Date.now() +  10 * 1000; // 3 นาที


        // เก็บ session ใน memory  // เก็บใน Sorage แล้ว
        sessions[sessionKey] = {
            username: user.username,
            type: user.type,
            supplier: user.supplier,
            expireTime
        };

        // ส่งข้อมูลกลับ client
        res.json({
            message: 'Login สำเร็จ',
            data: {
                username: user.username,
                type: user.type,
                supplier: user.supplier,
                loginTime: Date.now(),
                sessionKey,
                expireTime
            }
        });

        console.log('Login successful:', user.username); // Debug

    } catch (err) {
        console.error('Server Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.post('/api/check-session', (req, res) => {
    const { sessionKey } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ valid: false });
    }

    const session = sessions[sessionKey];

    // ตรวจสอบหมดอายุ
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey]; // ลบ session
        return res.status(401).json({ valid: false });
    }

    res.json({ valid: true, username: session.username, type: session.type });
});



app.post('/api/get-regiscar-data', async (req, res) => {
    const { sessionKey } = req.body;

    // ตรวจสอบ sessionKey ใน memory
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    // ตรวจสอบหมดอายุ
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey]; // ลบ session
        return res.status(401).json({ message: 'Session expired' });
    }

    // ตรวจสอบว่าเป็น admin หรือไม่
    if (session.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    try {
        // ดึงข้อมูลจากฐานข้อมูล
        const [rows] = await pool.query('SELECT * FROM registrationsUser');
        
        res.json({
            success: true,
            data: rows
        });

    } catch (err) {
        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});


// ===== SERVER-SIDE API =====
app.post('/api/reject-user', async (req, res) => {
    const { sessionKey, username } = req.body;

    // ตรวจสอบ session
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey];
        return res.status(401).json({ message: 'Session expired' });
    }

    if (session.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }

    try {
        // ลบ user จากฐานข้อมูล
        const [result] = await pool.query(
            'DELETE FROM registrationsUser WHERE username = ?',
            [username]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        console.log(`User ${username} rejected and deleted by admin ${session.username}`);

        res.json({
            success: true,
            message: `ปฏิเสธและลบ User ${username} เรียบร้อย`,
            deletedUser: username
        });

    } catch (err) {
        console.error('Database Error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Server Error' 
        });
    }
});

// ======= ยอมรับ API =========
app.post('/api/accept-user', async (req, res) => {
    const { sessionKey, userData } = req.body;

    // ตรวจสอบ session
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey];
        return res.status(401).json({ message: 'Session expired' });
    }

    if (session.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    if (!userData || !userData.username) {
        return res.status(400).json({ message: 'User data is required' });
    }

    try {
        // ✅ ตรวจสอบว่า User มีอยู่ใน accounts แล้วหรือไม่
        const [existingUser] = await pool.query(
            'SELECT * FROM accounts WHERE username = ?',
            [userData.username]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'User already exists in accounts' });
        }

        // ✅ เพิ่ม User ลงในตาราง accounts (ใช้ข้อมูลที่ส่งมาจาก frontend)
        const [insertResult] = await pool.query(`
            INSERT INTO accounts (username, password_hash, supplier, type) 
            VALUES (?, ?, ?, ?)
        `, [
            userData.username,
            userData.password_hash,
            userData.supplier_name,
            'user'  // กำหนด type เป็น 'user' ทั้งหมด
        ]);

        // ✅ ลบ User จาก registrationsUser (หลังจาก accept แล้ว)
        await pool.query(
            'DELETE FROM registrationsUser WHERE username = ?',
            [userData.username]
        );

        console.log(`User ${userData.username} accepted and moved to accounts by admin ${session.username}`);

        res.json({
            success: true,
            message: `ยอมรับ User ${userData.username} เรียบร้อย`,
            acceptedUser: {
                username: userData.username,
                type: 'user'
            }
        });

    } catch (err) {
        console.error('Database Error:', err);
        
        // ถ้าเกิด error ขณะ insert อาจต้อง rollback
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Username already exists' });
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Server Error' 
        });
    }
});

// ============================== Login Admin or User End  ===============================================================================


















// ============================== Program Truck-Side ================================================================================

// ทดสอบไว้ลงทะเบียน user ที่เข้ารหัสฝั่งรถบรรทุก 
app.post('/registerforuserTruck', async (req, res) => {
    try {
        const { user, password } = req.body;

        if (!user || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        const password_hash = await bcrypt.hash(password, 10); 

        const [result] = await pool.execute(
            'INSERT INTO userlocalprogram (user, password_hash) VALUES (?, ?)',
            [user, password_hash]
        );

        res.status(201).json({ message: ' เพิ่มข้อมูลแล้ว', userId: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

const loginLimiterTokenTruck = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 นาที
    max: 3, // จำกัด 5 ครั้งต่อ 15 นาที (เข้มงวดกว่า)
    message: {
        error: 'มีการพยายามเข้าสู่ระบบมากเกินไป กรุณารอ 15 นาที'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware ตรวจสอบ Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']; 
  let token;

  if (authHeader) {
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1]; // แบบ Bearer
    } else {
      token = authHeader; // แบบส่งแค่ token
    }

    if (!token) return res.status(401).json({ message: 'Token not found' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Token invalid or expired' });
      req.user = user;
      next();
    });
  } else {
    return res.status(401).json({ message: 'Token not found' });
  }
}

app.post('/login' ,loginLimiterTokenTruck , async (req, res) => { // สำหรับ ขอ Token ฝั่ง Truck 
  const { user, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM userlocalprogram WHERE user = ?', [user]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'User not found' });
    }

    const dbUser = rows[0];

    // เข้ารหัส
    const match = await bcrypt.compare(password, dbUser.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Invalid password' });
    }
    const token = jwt.sign(
      { id: dbUser.id, user: dbUser.user },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }   // Token อายุ 15 นาที
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/users', authenticateToken, loginLimiterTokenTruck , async (req, res) => {
  try {
    // ดึงข้อมูลทั้งหมดจาก table regiscar
    const [rows] = await pool.query('SELECT * FROM regiscar')

    res.json(rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ============================== Program Truck-Side END ===============================================================================







app.post('/addDataMySQL', async (req, res) => {
    try {
        const dataList = req.body;
        
        // ตรวจสอบข้อมูล
        if (!Array.isArray(dataList) || dataList.length === 0) {
            return res.status(400).json({ message: 'No Data provided' });
        }
        
        // เชื่อมต่อฐานข้อมูล
        const conn = await pool.getConnection(); 
        
        try {
            await conn.beginTransaction();
            
            // วนลูปเพื่อ insert ข้อมูล
            for (const item of dataList) {
                const {
                    subblier,
                    fullname,
                    carNumber,
                    product,
                    company,
                    weightDate,
                    weightTime
                } = item;
                
                // ตรวจสอบข้อมูลที่จำเป็น
                if (!subblier || !fullname || !product || !company || !weightDate || !weightTime) {
                    throw new Error('Missing required fields');
                }
                
                await conn.query(
                    `INSERT INTO regiscar (NameSupplier, FullName, NumberCar , Product, Company, \`Date\`, \`Time\`) 
                     VALUES (?, ?, ?, ?, ?, ? , ?)`,
                    [subblier, fullname, carNumber, product, company, weightDate, weightTime]
                );
            }
            
            await conn.commit();
            res.status(200).json({ 
                message: 'Data inserted successfully',
                insertedCount: dataList.length 
            });
            
        } catch (err) {
            await conn.rollback();
            console.error('Database transaction error:', err);
            res.status(500).json({ message: 'Database error', error: err.message });
        } finally {
            conn.release();
        }
        
    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.get('/getdataCar', async (req, res)=>{
    const results = await pool.query('SELECT * FROM regiscar')
    res.json(results[0])
});
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
    console.log(`API Endpoints:`);
    console.log(`POST /api/generatecode - สร้างรหัส`);
    console.log(`POST /api/verify-code - ตรวจสอบรหัส`);
    console.log(`GET /api/codes - ดูรหัสทั้งหมด`);
});




