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
const fs = require('fs');
//const logPath = path.join(__dirname, 'logs.txt'); // เก็บ log 
const logsDir = path.join(__dirname, 'logs');


require('dotenv').config();

const app = express();
 const port = 3000;

// รัน Server ด้วย nodemon is : npx nodemon server.js

const corsOptions = {
       origin: [
    'http://localhost:3000',
    'http://127.0.0.1:5500',
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
    queueLimit: 0,
    dateStrings: true
});

// ฟังก์ชันเขียน log
// สร้างโฟลเดอร์ถ้ายังไม่มี
function writeLog(message) {
    try {
        // ถ้าโฟลเดอร์ logs ยังไม่มี ให้สร้างใหม่
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }

        // 📅 ตั้งชื่อไฟล์ log ตามวันที่ เช่น 2025-10-16.txt
        const today = new Date().toISOString().slice(0, 10); // yyyy-mm-dd
        const logFilePath = path.join(logsDir, `${today}.txt`);

        // 🕒 เพิ่มเวลาพร้อมข้อความ
        const timestamp = new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' });
        const logMessage = `[${timestamp}] ${message}\n`;

        // ✍️ เขียน log ลงไฟล์ (เพิ่มต่อท้าย)
        fs.appendFileSync(logFilePath, logMessage, 'utf8');

        console.log('✅ Log saved:', logMessage.trim());  // สำหรับไว้ Debug


    } catch (err) {
        console.error('❌ Error writing log:', err.message);
    }
}


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
    windowMs: 5 * 60 * 1000, // 15 นาที
    max: 3, // จำกัด 3 ครั้งต่อ 15 นาที
    message: {
        error: 'Too many registration attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

// API Endpoint สำหรับการลงทะเบียนผู้ใช้งาน
app.post('/api/register', meddlewareRegisterUser, async (req, res) => {
    try {
        // ดึงข้อมูลจาก body
        const { fullName, username, password, phone, supplierName , department } = req.body;

        // ตรวจสอบข้อมูลที่จำเป็น
        if (!fullName || !username || !password || !phone || !supplierName || !department) {
            return res.status(400).json({
                error: 'Please provide full name, username, password, and phone number.'
            });
        }

        // ถ้าต้องการมีการแฮชรหัสผ่าน 
      //const hashedPassword = await bcrypt.hash(password, 10);

       const conn = await pool.getConnection(); // รอรับ connection จาก pool การเชื่อมต่อฐานข้อมูลก่อน 

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
            INSERT INTO registrationsUser (full_name, username, password_hash, phone, supplier_name , department)
            VALUES (?, ?, ?, ?, ? , ?)
        `;

        const values = [
            fullName,
            username,
          //hashedPassword,
          password,
            phone,
            supplierName ,
            department
        ];

        const [result] = await conn.execute(sql, values);

         // เขียน log ลงทะเบียนสำเร็จ
        writeLog(`====================================== Register Success (ผู้ลงทะเบียน) =================================
ข้อมูลผู้ลงทะเบียน:
fullName: ${fullName}
username: ${username}
password: ${password}
phone: ${phone}
supplierName: ${supplierName}
department: ${department}
สถานะ: ✅ ลงทะเบียนสำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        return res.status(201).json({
            message: 'User registered successfully!',
            userId: result.insertId
        });

    } catch (error) {

         writeLog(`====================================== Register Error (ผู้ลงทะเบียน) =================================
username: ${req.body.username || 'ว่าง'}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างลงทะเบียน
รายละเอียด: ${error.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Error during user registration:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    } finally {
        if (conn) conn.release(); // ปล่อย connection เสมอ
    }
});

// =============================================== API ลงทะเบียน เก็บข้อมูล  END ======================================================



// ============================== Login Admin or User V 2  =========================================================================

const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 นาที
    max: 50, // จำกัด 5 ครั้งต่อ 15 นาที (เข้มงวดกว่า)
    message: {
        error: 'มีการพยายามเข้าสู่ระบบมากเกินไป กรุณารอ 2 นาที'
    },
    standardHeaders: true,
    legacyHeaders: false,
});



//const activeSessions = new Map();
const sessions = {};
const activeUsers = new Map(); // เก็บ username ที่กำลัง login อยู่

// Login route
app.post('/loginAdminandUser', loginLimiter, async (req, res) => {

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'กรุณาใส่กรอกข้อมูล user และ password' });
    }

    try {

        const conn = await pool.getConnection(); // รอรับ connection จาก pool การเชื่อมต่อฐานข้อมูลก่อน

        const [result] = await conn.query(
            'SELECT * FROM accounts WHERE username = ? AND password_hash = ?',
            [username, password]
        );


        if (result.length === 0) {
writeLog(`====================================== Login Failed (ผู้เข้าใช้งานระบบไม่ผ่าน)  ❌ =================================
ชื่อผู้ใช้ (Username): ${username}
หรัสผ่าน (Password): ${password}
สถานะ: ❌ เข้าระบบไม่สำเร็จ (User หรือ Password ไม่ถูกต้อง)
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
            return res.status(401).json({ message: 'User หรือ Password ไม่ถูกต้อง' });
        }

        const user = result[0];

                // 🔹 เช็คว่ามี User นี้ login อยู่แล้วหรือไม่
        if (activeUsers.has(username)) {
            const existingSession = activeUsers.get(username);
            
            // เช็คว่า session เดิมยังไม่หมดอายุ
            if (existingSession.expireTime > Date.now()) {
                writeLog(`====================================== Login Rejected (มีผู้ใช้งานอยู่แล้ว) 🚫 =================================
ชื่อผู้ใช้ (Username): ${username}
ประเภทผู้ใช้ (User Type): ${user.type}
สถานะ: 🚫 มีผู้ใช้งาน login อยู่แล้ว
เวลาที่พยายาม login: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
                return res.status(409).json({ 
                    message: 'มีผู้ใช้งาน login อยู่แล้ว ไม่สามารถ login ซ้ำได้',
                    alreadyLoggedIn: true
                });
            } else {
                // ถ้า session เดิมหมดอายุแล้ว ให้ลบออก
                delete sessions[existingSession.sessionKey];
                activeUsers.delete(username);
            }
        }


      let departmentData = null;
 // เก็บเฉพาะค่า department
    if (user.type === 'user') {
            departmentData = user.department;
        } else if (user.type == 'admin'){
            departmentData = user.department;
        } else if (user.type == 'superadmin'){
            departmentData = user.department;
        }


        // สร้าง session key
        const sessionKey = crypto.randomBytes(16).toString('hex');
        const expireTime = Date.now() + 24 * 60 * 60 * 1000; // 24 ชั่วโมง
       // const expireTime = Date.now() + 1 * 60 * 1000; //  1 นาที
        //const expireTime = Date.now() +  10 * 1000; // 10 วินาที


        // เก็บ session key ของและ user ที่ login ผ่าน ไว้ที่ Memory sessions และ ส่งไปหา Client  // เก็บใน Sorage แล้ว
        sessions[sessionKey] = {
            username: user.username,
            type: user.type,
            supplier: user.supplier,
            expireTime
        };

         // 🔹 เก็บข้อมูล user ที่กำลัง login อยู่
        activeUsers.set(username, {
            sessionKey: sessionKey,
            expireTime: expireTime,
            type: user.type
        });

       // เขียน log
writeLog(`====================================== Login Success (ผู้เข้าใช้งานระบบสำเสร็จ) ✅ =================================
ข้อมูลผู้ Login
ชื่อผู้ใช้ (Username): ${username}
ประเภทผู้ใช้ (User Type): ${user.type}
แผนก (Department): ${user.department}
ซัพพลายเออร์ (Supplier): ${user.supplier}
เวลาเข้าใช้งาน: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
===============================================================================================
`);


        // ส่งข้อมูลกลับ client
        res.json({
            message: 'Login สำเร็จ',
            data: {
                username: user.username,
                type: user.type,
                supplier: user.supplier,
                loginTime: Date.now(),
                sessionKey,
                expireTime,
                departmentData
            }
        });


    } catch (err) {
       
writeLog(`====================================== Login Error (ผู้เข้าใช้งานระบบ server / exception) ⚠️ =================================
ชื่อผู้ใช้ (Username): ${username}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างการเข้าสู่ระบบ (Login)
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Server Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});


// 🔹 API สำหรับ Logout (ต้องเพิ่มเพื่อลบ session)
app.post('/logout-adminanduser', async (req, res) => {
    const { sessionKey } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];
    const username = session.username;

    // ลบ session และ active user
    delete sessions[sessionKey];
    activeUsers.delete(username);

    writeLog(`====================================== Logout Success ✅ =================================
ชื่อผู้ใช้ (Username): ${username}
เวลา Logout: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
===============================================================================================
`);

    res.json({
        success: true,
        message: 'Logout สำเร็จ'
    });
});

// 🔹 ทำความสะอาด session ที่หมดอายุ (ควรรันเป็นระยะ)
setInterval(() => {
    const now = Date.now();
    
    // ลบ sessions ที่หมดอายุ
    for (const [sessionKey, session] of Object.entries(sessions)) {
        if (session.expireTime < now) {
            const username = session.username;
            delete sessions[sessionKey];
            activeUsers.delete(username);
            
            writeLog(`====================================== Session Expired 🕐 =================================
ชื่อผู้ใช้ (Username): ${username}
เวลาที่ Session หมดอายุ: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
===============================================================================================
`);
        }
    }
}, 5 * 60 * 1000); // เช็คทุก 5 นาที



// Enpoint สำหรับ admin and SuperAdmin ดึงข้อมูล User ที่ได้ Register
app.post('/admin/get-regiscar-data', async (req, res) => {
    const { sessionKey, type, departmentData } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {
        let rows;

        if (type === 'admin') {
            // สำหรับ admin เอาแค่ department ของตัวเอง
            rows = await pool.query('SELECT * FROM registrationsUser WHERE department = ?', [departmentData]);
        } else if (type === 'superadmin') {
            // สำหรับ superadmin เอาทั้งหมด
            rows = await pool.query('SELECT * FROM registrationsUser');
        } else {
            return res.status(403).json({ message: 'Access denied' });
        }

        res.json({
            success: true,
            data: rows[0] || rows // ถ้าใช้ mysql2 promise จะ return [rows, fields]
        });

                // Log การดึงข้อมูลสำเร็จ
        writeLog(`====================================== Get-Register Data Success =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${type}, department = ${departmentData || 'ว่าง'}
สถานะ: ✅ ดึงข้อมูลสำเร็จ
จำนวนรายการที่ดึงได้: ${rows[0]?.length || rows.length || 0}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

    } catch (err) {

         // เขียน log กรณีเกิด Error
        writeLog(`====================================== Enpoint /admin/get-regiscar-data  สำหรับ admin and SuperAdmin ดึงข้อมูล User ที่ได้ Register  Get-Register Data Error =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${type}, department = ${departmentData || 'ว่าง'}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างดึงข้อมูล
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});



// Enpoint admin and SuperAdmin ปฎิเสฐ  User Register =====
app.post('/api/reject-user', async (req, res) => {
    const { sessionKey, username } = req.body;
        const session = sessions[sessionKey];
    // ตรวจสอบ session
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }
   
     if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    if (session.type !== 'admin' && session.type !== 'superadmin') {
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

// Enpoint admin and SuperAdmin ยอมรับ  User Register =====
app.post('/api/accept-user', async (req, res) => {
    const { sessionKey, userData } = req.body;

     const session = sessions[sessionKey];

    // ตรวจสอบ sessionKey จาก Memory 
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

   
    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    if (session.type !== 'admin' && session.type !== 'superadmin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }
    // ตรวจสอบ Req ที่ส่งมาว่า username ไหม 
    if (!userData || !userData.username) {
        return res.status(400).json({ message: 'User data is required' });
    }

    try {

         await pool.query(`
            INSERT INTO accounts (fullname, username, password_hash, supplier, type , department, phone) 
            VALUES (?, ?, ?, ?, ?, ?,?)
        `, [
            userData.fullname,
            userData.username,
            userData.password_hash,
            userData.supplier_name,
            'user',
            userData.department,
            userData.phone
        ]);

        //  ลบ User จาก registrationsUser (หลังจาก accept แล้ว)
        await pool.query(
            'DELETE FROM registrationsUser WHERE username = ?',
            [userData.username]
        );

         // Log การ reject สำเร็จ
        writeLog(`====================================== Reject User Success ปฏิเสธผู้ที่ Register =================================
ผู้ดำเนินการ: sessionKey = ${sessionKey}, type = ${session.type}
Username ที่ reject: ${username}
สถานะ: ✅ ปฏิเสธและลบ User สำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

        res.json({
            success: true,
            message: `ยอมรับ User ${userData.username} เรียบร้อย`,
            acceptedUser: {
                username: userData.username,
                type: 'user'
            }
        });

    } catch (err) {

         // Log กรณีเกิด Error
        writeLog(`====================================== Reject User Error =================================
ผู้ดำเนินการ: sessionKey = ${sessionKey}, type = ${session.type}
Username ที่ reject: ${username}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างลบผู้ใช้
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database Error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Server Error' 
        });
    }
});

// เพิ่ม Admin สำหรับ SuperAdmin
app.post('/api/add-admin', async (req, res) => {
    const { sessionKey, userData } = req.body;
    const session = sessions[sessionKey];

    if (!sessionKey || !session) return res.status(401).json({ message: 'Session not found' });
    if (Date.now() > session.expireTime) return res.status(401).json({ message: 'Session expired' });
    if (session.type !== 'superadmin') return res.status(403).json({ message: 'Access denied. Superadmin only' });

    if (!userData || !userData.username || !userData.type || !userData.department) {
        return res.status(400).json({ message: 'User data is required' });
    }

    try {
        await pool.query(`
            INSERT INTO accounts (fullname, username, password_hash, supplier, type, department, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            userData.fullname,
            userData.username,
            userData.password_hash,
            "-",            // supplier เป็น "-"
            userData.type,  // admin หรือ superadmin
            userData.department,
            "-"
        ]);

         writeLog(`====================================== SuperAdmin Add Admin Success =================================
ผู้ดำเนินการ: sessionKey = ${sessionKey}, type = ${session.type}
ข้อมูลผู้ใช้ที่เพิ่ม:
fullname: ${userData.fullname}
username: ${userData.username}
type: ${userData.type}
department: ${userData.department}
สถานะ: ✅ เพิ่มผู้ใช้สำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        res.json({
            success: true,
            message: `เพิ่ม ${userData.type} ${userData.username} เรียบร้อย`,
            addedUser: userData
        });
    } catch (err) {
        // Log กรณีเกิด Error
        writeLog(`====================================== Add Admin Error =================================
ผู้ดำเนินการ: sessionKey = ${sessionKey}, type = ${session.type}
ข้อมูลผู้ใช้ที่เพิ่ม:
fullname: ${userData.fullname}
username: ${userData.username}
type: ${userData.type}
department: ${userData.department}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างเพิ่มผู้ใช้
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database Error:', err);
       if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Username already exists' });
        } 
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

//==========================================================


// Enpoint สำหรับ Admin , SuperAdmin ดู ข้อมูลรถที่ได้ลงทะเบียน  เพื่อกด ยอมรับ Order หรือ  ไม่ยอมรับ Order  
app.post('/admin/get-regiscar-data-order', async (req, res) => {
    const { sessionKey, departmentData } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    // เช็คสิทธิ์
    if (session.type !== 'admin' && session.type !== 'superadmin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    try {

        let rows;

        if(session.type === 'superadmin' || departmentData === 'superadmin'){
            [rows] = await pool.query('SELECT * FROM regiscar');
        }else{
             [rows] = await pool.query(
                'SELECT * FROM regiscar WHERE department = ?',
                [departmentData]
            );
        }

       
        res.json({
            success: true,
            departmentData: departmentData,
            data: rows
        });

         // Log SELECT สำเร็จ
        writeLog(`====================================== Get Regiscar Data Order Success Admin , SuperAdmin ดู ข้อมูลรถที่ได้ลงทะเบียน  เพื่อกด ยอมรับ Order หรือ  ไม่ยอมรับ Order   =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Department: ${departmentData}
จำนวนรายการที่ดึงได้: ${rows.length || 0}
สถานะ: ✅ ดึงข้อมูลสำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

    } catch (err) {

        // Log กรณีเกิด Error
        writeLog(`====================================== Get Regiscar Data Order Error Admin , SuperAdmin ดู ข้อมูลรถที่ได้ลงทะเบียน  เพื่อกด ยอมรับ Order หรือ  ไม่ยอมรับ Order   =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Department: ${departmentData}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างดึงข้อมูล
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});


app.post('/admin/get-regiscar-data-order-success', async (req, res) => {//
    const { sessionKey, departmentData } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    // เช็คสิทธิ์
    if (session.type !== 'admin' && session.type !== 'superadmin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    try {

        let rows;

        if(session.type === 'superadmin' || departmentData === 'superadmin'){
            [rows] = await pool.query('SELECT * FROM regiscar_accepted');
        }else{
             [rows] = await pool.query(
                'SELECT * FROM regiscar_accepted WHERE Department = ?',
                [departmentData]
            );
        }

       
        res.json({
            success: true,
            departmentData: departmentData,
            data: rows
        });


    } catch (err) {


        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});


app.post('/super/get-dataAdmin', async (req, res) => {
    const { sessionKey, departmentData } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {
        const [rows] = await pool.query(
            'SELECT * FROM accounts WHERE type = ?', ['admin']
        );

        res.json({
            success: true,
            departmentData: departmentData,
            data: rows
        });

    } catch (err) {
        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.post('/get-data-User', async (req, res) => {
    const { sessionKey, departmentData } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    // เช็คสิทธิ์
    if (session.type !== 'admin' && session.type !== 'superadmin') {
        return res.status(403).json({ message: 'Access denied. Admin only' });
    }

    try {

        let rows;

        if(session.type === 'superadmin' || departmentData === 'superadmin'){
            [rows] = await pool.query('SELECT * FROM accounts WHERE type = ?', ['user']);
        }else{
             [rows] = await pool.query(
                'SELECT * FROM accounts WHERE type = ? AND department = ?',
                ['user',departmentData]
            );
        }

       
        res.json({
            success: true,
            departmentData: departmentData,
            data: rows
        });


    } catch (err) {

        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});


// API สำหรับลบ Admin
// API สำหรับลบ Admin
app.delete('/super/delete-admin', async (req, res) => {
    const { sessionKey, id } = req.body;

    // ตรวจสอบ Session
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ 
            success: false,
            message: 'Session not found' 
        });
    }

    const session = sessions[sessionKey];

    // ตรวจสอบว่า Session หมดอายุหรือไม่
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey];
        return res.status(401).json({ 
            success: false,
            message: 'Session expired' 
        });
    }

    // ตรวจสอบว่ามี id หรือไม่
    if (!id) {
        return res.status(400).json({ 
            success: false,
            message: 'ID is required' 
        });
    }

    try {
        // ลบข้อมูลเลย
        const [result] = await pool.query(
            'DELETE FROM accounts WHERE id = ? AND type = ?',
            [id, 'admin']
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ 
                success: false,
                message: 'Admin not found or already deleted' 
            });
        }

        res.json({
            success: true,
            message: 'Admin deleted successfully',
            deletedId: id
        });

    } catch (err) {
        console.error('Database Error:', err);
        res.status(500).json({ 
            success: false,
            message: 'Server Error'
        });
    }
});

// API สำหรับลบ user
app.delete('/super/delete-user', async (req, res) => {
    const { sessionKey, id } = req.body;

    // ตรวจสอบ Session
    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ 
            success: false,
            message: 'Session not found' 
        });
    }

    const session = sessions[sessionKey];

    // ตรวจสอบว่า Session หมดอายุหรือไม่
    if (Date.now() > session.expireTime) {
        delete sessions[sessionKey];
        return res.status(401).json({ 
            success: false,
            message: 'Session expired' 
        });
    }

    // ตรวจสอบว่ามี id หรือไม่
    if (!id) {
        return res.status(400).json({ 
            success: false,
            message: 'ID is required' 
        });
    }

    try {
        // ตรวจสอบว่ามีข้อมูลอยู่จริงหรือไม่
        const [checkRows] = await pool.query(
            'SELECT id, username FROM accounts WHERE id = ? ',
            [id]
        );

        if (checkRows.length === 0) {
            return res.status(404).json({ 
                success: false,
                message: 'Admin not found' 
            });
        }

        // ลบข้อมูล
        const [result] = await pool.query(
            'DELETE FROM accounts WHERE id = ? AND type = ?',
            [id, 'admin']
        );

        if (result.affectedRows === 0) {
            return res.status(500).json({ 
                success: false,
                message: 'Failed to delete admin' 
            });
        }

        res.json({
            success: true,
            message: 'Admin deleted successfully',
            deletedId: id,
            deletedUsername: checkRows[0].username
        });

    } catch (err) {
        console.error('Database Error:', err);
        res.status(500).json({ 
            success: false,
            message: 'Server Error',
            error: err.message 
        });
    }
});


// Enpoint สำหรับ สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน แต่ยังไม่ถูกยอมรับจาก Admin , SuperAdmin
app.post('/user/get-btnViewRegisteredData', async (req, res) => {
    const { sessionKey, username } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {
        // หา id ของ user จาก accounts
        const [accountRows] = await pool.query(
            'SELECT id FROM accounts WHERE username = ? LIMIT 1',
            [username]
        );

        if (accountRows.length === 0) {
            return res.status(404).json({ message: 'Username not found in accounts' });
        }

        const id_user = accountRows[0].id;

       // ดึงข้อมูลจาก regiscar ของ user นี้
        const [regiscarRows] = await pool.query(
            'SELECT * FROM regiscar WHERE id_user = ?',
            [id_user]
        );

        res.json({
            success: true,
            data: regiscarRows
        });

        // Log SELECT สำเร็จ
        writeLog(`====================================== Get BtnViewRegisteredData Success สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน แต่ยังไม่ถูกยอมรับจาก Admin , SuperAdmin=================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Username: ${username}
จำนวนรายการที่ดึงได้: ${regiscarRows.length || 0}
สถานะ: ✅ ดึงข้อมูลสำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

    } catch (err) {

         // Log กรณีเกิด Error
        writeLog(`====================================== Get BtnViewRegisteredData Error สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน แต่ยังไม่ถูกยอมรับจาก Admin , SuperAdmin =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Username: ${username}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างดึงข้อมูล
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});

// Enpoint  สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน(เตียมเข้าชั่ง) และถูกยอมรับจาก Admin , SuperAdmin
app.post('/user/get-btnViewPendingOrders', async (req, res) => {
    const { sessionKey, username } = req.body;

    if (!sessionKey || !sessions[sessionKey]) {
        return res.status(401).json({ message: 'Session not found' });
    }

    const session = sessions[sessionKey];

    if (Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {
        // หา id ของ user จาก accounts
        const [accountRows] = await pool.query(
            'SELECT id FROM accounts WHERE username = ? LIMIT 1',
            [username]
        );

        if (accountRows.length === 0) {
            return res.status(404).json({ message: 'Username not found in accounts' });
        }

        const id_user = accountRows[0].id;

        // ดึงข้อมูลจาก ทั้งหมด 
        const [regiscarRows] = await pool.query(
            'SELECT * FROM regiscar_accepted WHERE id_user = ?',
            [id_user]
        );

        // ดึงข้อมูลแค่ Status Success
    //     const [regiscarRows] = await pool.query(
    // 'SELECT * FROM regiscar_accepted WHERE id_user = ? AND Status != "Success"',
    // [id_user]
//);

        res.json({
            success: true,
            data: regiscarRows
        });

        // Log SELECT สำเร็จ
        writeLog(`====================================== Get BtnViewPendingOrders Success  สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน(เตียมเข้าชั่ง) และถูกยอมรับจาก Admin , SuperAdmin =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Username: ${username}
จำนวนรายการที่ดึงได้: ${regiscarRows.length || 0}
สถานะ: ✅ ดึงข้อมูลสำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

    } catch (err) {
         // Log กรณีเกิด Error
        writeLog(`====================================== Get BtnViewPendingOrders Error  สำหรับ User ที่จะดูข้อมูลที่ได้ ลงทะเบียน(เตียมเข้าชั่ง) และถูกยอมรับจาก Admin , SuperAdmin =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
Username: ${username}
สถานะ: ⚠️ เกิดข้อผิดพลาดระหว่างดึงข้อมูล
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database Error:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});



// Enpoint สำหรับ ยอมรับ จาก Admin , SupderAdmin
app.post('/register-accepted', async (req, res) => {
    const { dataList, sessionKey } = req.body;

    const session = sessions[sessionKey];
    if (!session || Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {
        if (!Array.isArray(dataList) || dataList.length === 0) {
            return res.status(400).json({ message: 'No Data provided' });
        }

        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            for (const item of dataList) {
                const {
                    subblier,
                    fullname,
                    typecarTwo,
                    frontPlate,
                    rearPlate,
                    product,
                    department,
                    weightDate,
                    weightTime,
                    id_user,
                    id
                } = item;

                if (!subblier || !fullname || !typecarTwo || !frontPlate || !rearPlate || !product || !weightDate || !weightTime || !id_user) {
                    throw new Error('Missing required fields');
                }

                   //  ตัดเครื่องหมาย "-" ออกจาก frontPlate เพื่อเอา ค่าจากที่ตัดมาได้ใส่ฟิล frontPlateShort
                //const frontPlateShort = frontPlate.replace(/-/g, '');
                const frontPlateShort = frontPlate.replace(/[-\s]/g, '');


                await conn.query(
                    `INSERT INTO regiscar_accepted
                    (NameSupplier, FullName, TypeCar, FrontPlate, RearPlate, FrontPlateShort, Product, Department, \`Date\`, \`Time\` , Id_user, Status) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [subblier, fullname, typecarTwo, frontPlate, rearPlate, frontPlateShort, product, department, weightDate, weightTime, id_user, "Planning"]
                );

                await conn.query('DELETE FROM regiscar WHERE id = ?', [id]);
            }

            //  ต้อง ลบ ใน regis ใ้หได้

            await conn.commit();
 // Log INSERT สำเร็จ
            writeLog(`====================================== Register Accepted Success Enpoint สำหรับ ยอมรับ จาก Admin , SupderAdmin =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
จำนวนรายการที่ INSERT: ${dataList.length}
สถานะ: ✅ INSERT สำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);            
            res.status(200).json({
                message: 'Data inserted successfully',
                insertedCount: dataList.length
            });

        } catch (err) {
            await conn.rollback();
             // Log Error ระหว่าง Transaction
            writeLog(`====================================== Register Accepted Error =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
สถานะ: ⚠️ Transaction error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

            console.error('Database transaction error:', err);
            res.status(500).json({ message: 'Database error', error: err.message });
        } finally {
            conn.release();
        }

    } catch (err) {

          // Log Error Server
        writeLog(`====================================== Register Accepted Error =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session?.type || 'Unknown'}
สถานะ: ⚠️ Server error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

        console.error('Server error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// Enpoint สำหรับ ไม่ยอมรับ จาก Admin , SupderAdmin
app.post('/register-rejected', async (req, res) => { 
    const { id, sessionKey } = req.body;

    const session = sessions[sessionKey];
    if (!session || Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    if (!id) return res.status(400).json({ message: 'Missing id' });

    try {
        await pool.query('DELETE FROM regiscar WHERE id = ?', [id]);
        res.status(200).json({ message: 'Data deleted successfully', id: id });

         // Log DELETE สำเร็จ
        writeLog(`====================================== Delete Rejected Success =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session.type}
ID ที่ลบ: ${id}
สถานะ: ✅ DELETE สำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

    } catch (err) {

         // Log Error ระหว่าง DELETE
        writeLog(`====================================== Delete Rejected Error =================================
ผู้เรียกใช้งาน: sessionKey = ${sessionKey}, type = ${session?.type || 'Unknown'}
สถานะ: ⚠️ Database delete error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Database delete error:', err);
        res.status(500).json({ message: 'Database error', error: err.message });
    }
});


// Enpoint สำหรับ User เพิ่มข้อมูลลงฐานข้อมูล Regsicar 
app.post('/addDataMySQL', async (req, res) => {
    const { dataList, sessionKey, username } = req.body;

    const session = sessions[sessionKey];
    if (!session || Date.now() > session.expireTime) {
        return res.status(401).json({ message: 'Session expired' });
    }

    try {        
        if (!Array.isArray(dataList) || dataList.length === 0) {
            return res.status(400).json({ message: 'No Data provided' });
        }
        
        const conn = await pool.getConnection(); 
        
        try {
            await conn.beginTransaction();

            // ค้นหา id_user จาก accounts
            const [rows] = await conn.query(
                `SELECT id FROM accounts WHERE username = ? LIMIT 1`, // whe use limti , ? 
                [username]
            );

            if (rows.length === 0) {
                throw new Error('Username not found in accounts');
            }

            const id_user = rows[0].id;

            for (const item of dataList) {
                const {
                    subblier,
                    fullname,
                    typecarTwo,
                    frontPlate,
                    rearPlate,
                    product,
                    department,
                    weightDate,
                    weightTime
                } = item;

                if (!subblier || !fullname || !typecarTwo || !frontPlate || !rearPlate || !product || !weightDate || !weightTime) {
                    throw new Error('Missing required fields');
                }

                await conn.query(
                    `INSERT INTO regiscar 
                    (NameSupplier, FullName, TypeCar, FrontPlate, RearPlate, Product, department, \`Date\`, \`Time\`, id_user) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [subblier, fullname, typecarTwo, frontPlate, rearPlate, product, department, weightDate, weightTime, id_user]
                );
            }
            
            await conn.commit();

             // Log INSERT สำเร็จ
            writeLog(`====================================== Insert regiscar Success =================================
ผู้ใช้งาน: ${username} (sessionKey: ${sessionKey}, type: ${session.type})
จำนวนรายการที่เพิ่ม: ${dataList.length}
สถานะ: ✅ INSERT สำเร็จ
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
            res.status(200).json({ 
                message: 'Data inserted successfully',
                insertedCount: dataList.length 
            });
            
        } catch (err) {
            await conn.rollback();

             // Log Error ระหว่าง INSERT
            writeLog(`====================================== Insert regiscar Error =================================
ผู้ใช้งาน: ${username} (sessionKey: ${sessionKey}, type: ${session?.type || 'Unknown'})
สถานะ: ⚠️ Database transaction error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);

            console.error('Database transaction error:', err);
            res.status(500).json({ message: 'Database error', error: err.message });
        } finally {
            conn.release();
        }
        
    } catch (err) {

          // Log Error Server
        writeLog(`====================================== Insert regiscar Server Error =================================
ผู้ใช้งาน: ${username} (sessionKey: ${sessionKey}, type: ${session?.type || 'Unknown'})
สถานะ: ⚠️ Server error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
====================================================================================================
`);
        console.error('Server error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});






// ============================== Program Truck-Side ================================================================================


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


// ทดสอบไว้ลงทะเบียน user ที่เข้ารหัสฝั่งรถบรรทุก ที่เข้า รหัสไว้แล้ว 
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


app.post('/login' ,loginLimiterTokenTruck , async (req, res) => { // สำหรับ login ขอ Token ฝั่ง Truck 
  const { user, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM userlocalprogram WHERE user = ?', [user]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'User not found' });
    }

    const dbUser = rows[0];

    // เข้ารหัส
    // const match = await bcrypt.compare(password, dbUser.password_hash);
    // if (!match) {
    //   return res.status(401).json({ message: 'Invalid password' });
    // }

    // ไม่ต้องเข้าหรัส
    if (password !== dbUser.password_hash) { // ถ้าเปลี่ยนชื่อ column เป็น password ให้ใช้ dbUser.password
      return res.status(401).json({ message: 'Invalid password' });
    }


    const token = jwt.sign(
      { id: dbUser.id, user: dbUser.user },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }   // Token อายุ 15 นาที
    );
    res.json({ token });

     // Log login สำเร็จ
        writeLog(`====================================== Login Truck Success =================================
ผู้ใช้งาน: ${user}
สถานะ: ✅ Login สำเร็จ, Token ถูกสร้าง
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);

  } catch (err) {

     // Log Error Server
        writeLog(`====================================== Login Truck Server Error =================================
ผู้ใช้งาน: ${user || 'Unknown'}
สถานะ: ⚠️ Server error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// get data หลังจาก ได้ Token
app.get('/users', authenticateToken, loginLimiterTokenTruck , async (req, res) => {
  try {
    // ดึงข้อมูลทั้งหมดจาก table regiscar
    const [rows] = await pool.query('SELECT * FROM regiscar_accepted')

     // Log SELECT สำเร็จ
        writeLog(`====================================== SELECT regiscar_accepted Success =================================
ผู้ใช้งาน: ${req.user.user}  // req.user มาจาก authenticateToken
สถานะ: ✅ SELECT สำเร็จ, ดึงข้อมูลทั้งหมด
จำนวนแถว: ${rows.length}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
    res.json(rows);

  } catch (err) {
     // Log Error
        writeLog(`====================================== SELECT regiscar_accepted Error =================================
ผู้ใช้งาน: ${req.user ? req.user.user : 'Unknown'}
สถานะ: ⚠️ Database error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
    console.error("Database error:", err);
    res.status(500).json({ message: 'Server error' });
  }
});


// เปลี่ยน status
/*
app.post('/users/update-status',  async (req, res) => {
  try {
    const { id , Status } = req.body; // รับ id ของแถวที่ต้องการอัปเดต

    if (!id && !Status) {
      return res.status(400).json({ message: 'กรุณาระบุ id ของข้อมูลที่ต้องการอัปเดต' });
    }

    // อัปเดตฟิลด์ status จาก Pending → Success
    const [result] = await pool.query(
      'UPDATE regiscar_accepted SET Status = "Success" WHERE id = ? AND Status = "Pending"',
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'ไม่พบข้อมูลที่เป็น Pending ตาม id ที่ระบุ' });
    }

    res.json({ message: 'อัปเดตสถานะสำเร็จ', id, newStatus: 'Success' });
  } catch (err) {
    console.error('❌ Database error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
*/

app.post('/users/update-status', async (req, res) => {
  try {
    const { Id, Status } = req.body; // รับ id และค่า Status จาก body

    // ตรวจสอบว่ามีค่าครบไหม
    if (!Id || !Status) {
      return res.status(400).json({ message: 'กรุณาระบุ id และ Status ที่ต้องการอัปเดต' });
    }

    // อัปเดตค่า Status ด้วยค่าที่ส่งมา
    const [result] = await pool.query(
      'UPDATE regiscar_accepted SET Status = ? WHERE id = ?',
      [Status, Id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'ไม่พบข้อมูลตาม id ที่ระบุ' });
    }

      // Log UPDATE สำเร็จ
    writeLog(`====================================== UPDATE regiscar_accepted Success =================================
สถานะ: ✅ UPDATE สำเร็จ
id: ${Id}
ค่า Status ใหม่: ${Status}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);

    res.json({ message: 'อัปเดตสถานะสำเร็จ', Id, newStatus: Status });

  } catch (err) {
    // Log Error Database
    writeLog(`====================================== UPDATE regiscar_accepted Error =================================
สถานะ: ⚠️ Database error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
    console.error('❌ Database error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});




// ============================== Program Truck-Side END ===============================================================================


// สำสรับดึงข้อมูลทะเบียนรถให้พี่กริน
// app.post('/querygetdatacar', async (req, res) => {
//   try {
//     const { FrontPlateShort, Status } = req.body; // ✅ รับเฉพาะ 2 ฟิลด์ที่ต้องการ

//     // ตรวจสอบว่ามีค่าอย่างน้อยหนึ่งค่า
//     if (!FrontPlateShort && !Status) {
//       return res.status(400).json({ message: 'Please provide FrontPlateShort or Status for search' });
//     }

//     let query = 'SELECT * FROM regiscar_accepted WHERE 1=1';
//     const params = [];

//     if (FrontPlateShort) {
//       query += ' AND FrontPlateShort = ?';
//       params.push(FrontPlateShort);
//     }

//     if (Status) {
//       query += ' AND Status = ?';
//       params.push(Status);
//     }

//     const [rows] = await pool.query(query, params);

//     if (rows.length === 0) {
//       return res.status(202).json({ message: 'ไม่มีข้อมูลป้ายทะเบียนนี้ในฐานข้อมูล' });
//     }

//     res.status(200).json({const:rows.length,message : rows});

//   } catch (err) {
//     console.error("Database error:", err);
//     res.status(500).json({ message: 'Server error', error: err.message });
//   }
// });

app.post('/querygetdatacar', async (req, res) => {
  try {
    const { FrontPlateShort, Status } = req.body; 

    // ตรวจสอบว่ามีค่าอย่างน้อยหนึ่งค่า
    if (!FrontPlateShort && !Status) {
      return res.status(400).json({ message: 'Please provide FrontPlateShort or Status for search' });
    }

    // ✅ ใช้วันที่ปัจจุบัน (รูปแบบ YYYY-MM-DD)
    const currentDate = new Date().toISOString().slice(0, 10);

    let query = 'SELECT * FROM regiscar_accepted WHERE 1=1';
    const params = [];

    if (FrontPlateShort) {
      query += ' AND FrontPlateShort = ?';
      params.push(FrontPlateShort);
    }

    if (Status) {
      query += ' AND Status = ?';
      params.push(Status);
    }

    // ✅ กรองข้อมูลตามวันปัจจุบันอัตโนมัติ
    query += ' AND DATE(`Date`) = ?';
    params.push(currentDate);

    const [rows] = await pool.query(query, params);

    if (rows.length === 0) {

          // Log SELECT สำเร็จ แต่ไม่มีข้อมูล
      writeLog(`====================================== QUERY regiscar_accepted =================================
สถานะ: ⚠️ ไม่มีข้อมูล
FrontPlateShort: ${FrontPlateShort || "-"}
Status: ${Status || "-"}
วันที่: ${currentDate}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
      return res.status(202).json({ message: `ไม่มีข้อมูลของวันที่ ${currentDate} ในฐานข้อมูล` });
    }

    // res.status(200).json({
    //   date: currentDate,
    //   count: rows.length,
    //   message: rows
    // });

     // Log SELECT สำเร็จ
    writeLog(`====================================== QUERY regiscar_accepted =================================
สถานะ: ✅ SELECT สำเร็จ
FrontPlateShort: ${FrontPlateShort || "-"}
Status: ${Status || "-"}
วันที่: ${currentDate}
จำนวนผลลัพธ์: ${rows.length}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);

    res.status(200).json({const:rows.length,message : rows});

  } catch (err) {

    // Log Database Error
    writeLog(`====================================== QUERY regiscar_accepted Error =================================
สถานะ: ⚠️ Database error
รายละเอียด: ${err.message}
เวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}
==============================================================================================
`);
    console.error("Database error:", err);
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




