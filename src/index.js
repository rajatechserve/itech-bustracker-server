require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const multer = require('multer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const DB_FILE = path.join(__dirname, '..', 'app.db');
const UPLOADS_DIR = path.join(__dirname, '..', 'uploads');
const db = new sqlite3.Database(DB_FILE);
const initDb = require('./dbInit');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Deprecated: serving static files. We will prefer DB-stored images via routes.
app.use('/uploads', express.static(UPLOADS_DIR));

// Configure multer for file uploads
// Memory storage for storing images in DB, not filesystem
const memoryStorage = multer.memoryStorage();

const uploadMem = multer({
    storage: memoryStorage,
    limits: {
        fileSize: 1 * 1024 * 1024 // default 1MB; specific routes will override
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only image files (JPEG, PNG, GIF, WEBP) are allowed'));
        }
    }
});

function runSql(sql, params = [])
{
    return new Promise((resolve, reject) =>
    {
        db.run(sql, params, function (err)
        {
            if (err) reject(err);
            else resolve(this);
        });
    });
}
function allSql(sql, params = [])
{
    return new Promise((resolve, reject) =>
    {
        db.all(sql, params, (err, rows) =>
        {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}
function getSql(sql, params = [])
{
    return new Promise((resolve, reject) =>
    {
        db.get(sql, params, (err, row) =>
        {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// Initialize database schema & seed default admin.
initDb(db);

// Verify tables exist; create if somehow missing (defensive for older db files).
const REQUIRED_TABLES = ['admins','drivers','students','parents','buses','routes','attendance','assignments','schools'];
function ensureTables() {
    db.serialize(() => {
        REQUIRED_TABLES.forEach(tbl => {
            db.get("SELECT name FROM sqlite_master WHERE type='table' AND name=?", [tbl], (err, row) => {
                if (err) {
                    console.error('Table check error for', tbl, err.message);
                    return;
                }
                if (!row) {
                    console.warn(`Missing table '${tbl}', creating now.`);
                    switch (tbl) {
                        case 'admins': db.run(`CREATE TABLE IF NOT EXISTS admins(id TEXT PRIMARY KEY, username TEXT UNIQUE, passwordHash TEXT)`); break;
                        case 'drivers': db.run(`CREATE TABLE IF NOT EXISTS drivers(id TEXT PRIMARY KEY, name TEXT, phone TEXT, license TEXT, schoolId TEXT)`); break;
                        case 'students': db.run(`CREATE TABLE IF NOT EXISTS students(id TEXT PRIMARY KEY, name TEXT, cls TEXT, parentId TEXT, busId TEXT, routeId TEXT, schoolId TEXT, pickupLocation TEXT)`); break;
                        case 'parents': db.run(`CREATE TABLE IF NOT EXISTS parents(id TEXT PRIMARY KEY, name TEXT, phone TEXT, schoolId TEXT)`); break;
                        case 'buses': db.run(`CREATE TABLE IF NOT EXISTS buses(id TEXT PRIMARY KEY, number TEXT, driverId TEXT, routeId TEXT, started INTEGER DEFAULT 0, lat REAL, lng REAL, schoolId TEXT, registrationStartDate TEXT, registrationExpiredDate TEXT, fcRenewalDate TEXT, busType TEXT)`); db.all("PRAGMA table_info(buses)", (e, rows)=>{ if(!e && rows && !rows.some(c=>c.name==='routeId')) db.run("ALTER TABLE buses ADD COLUMN routeId TEXT"); if(!e && rows && !rows.some(c=>c.name==='schoolId')) db.run("ALTER TABLE buses ADD COLUMN schoolId TEXT"); if(!e && rows && !rows.some(c=>c.name==='registrationStartDate')) db.run("ALTER TABLE buses ADD COLUMN registrationStartDate TEXT"); if(!e && rows && !rows.some(c=>c.name==='registrationExpiredDate')) db.run("ALTER TABLE buses ADD COLUMN registrationExpiredDate TEXT"); if(!e && rows && !rows.some(c=>c.name==='fcRenewalDate')) db.run("ALTER TABLE buses ADD COLUMN fcRenewalDate TEXT"); if(!e && rows && !rows.some(c=>c.name==='busType')) db.run("ALTER TABLE buses ADD COLUMN busType TEXT"); }); break;
                        case 'routes': db.run(`CREATE TABLE IF NOT EXISTS routes(id TEXT PRIMARY KEY, name TEXT, stops TEXT, busId TEXT, schoolId TEXT)`); break;
                        case 'attendance': db.run(`CREATE TABLE IF NOT EXISTS attendance(id TEXT PRIMARY KEY, studentId TEXT, busId TEXT, timestamp INTEGER, status TEXT, schoolId TEXT)`); break;
                        case 'assignments': db.run(`CREATE TABLE IF NOT EXISTS assignments(id TEXT PRIMARY KEY, driverId TEXT, busId TEXT, routeId TEXT, schoolId TEXT, trips TEXT)`); break;
                        case 'schools':
                            db.run(`CREATE TABLE IF NOT EXISTS schools(id TEXT PRIMARY KEY, name TEXT, address TEXT, city TEXT, state TEXT, county TEXT, phone TEXT, mobile TEXT, username TEXT UNIQUE, passwordHash TEXT, logo TEXT, photo TEXT)`);
                            db.all("PRAGMA table_info(schools)", (e, rows)=>{ if(e||!rows) return; const have=(c)=>rows.some(r=>r.name===c); const cols=[['city','TEXT'],['state','TEXT'],['county','TEXT'],['phone','TEXT'],['mobile','TEXT'],['username','TEXT'],['passwordHash','TEXT'],['logo','TEXT'],['photo','TEXT']].filter(([c])=>!have(c)); cols.forEach(([c,t])=> db.run(`ALTER TABLE schools ADD COLUMN ${c} ${t}`)); if(have('username')) db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_username ON schools(username)'); });
                            break;
                    }
                }
            });
        });
        // Trip persistence tables
        db.run(`CREATE TABLE IF NOT EXISTS trips(
            id TEXT PRIMARY KEY,
            busId TEXT,
            driverId TEXT,
            schoolId TEXT,
            direction TEXT,
            startedAt INTEGER,
            stoppedAt INTEGER,
            status TEXT
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS trip_locations(
            id TEXT PRIMARY KEY,
            tripId TEXT,
            busId TEXT,
            lat REAL,
            lng REAL,
            pingAt INTEGER
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS trip_events(
            id TEXT PRIMARY KEY,
            tripId TEXT,
            busId TEXT,
            type TEXT,
            data TEXT,
            createdAt INTEGER
        )`);
    });
}
ensureTables();

// Migration: Add new columns if they don't exist
function migrateDatabase() {
    db.serialize(() => {
        // Add trips column to assignments table
        db.run(`ALTER TABLE assignments ADD COLUMN trips TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (assignments.trips):', err.message);
            }
        });
        
        // Add pickupLocation column to students table
        db.run(`ALTER TABLE students ADD COLUMN pickupLocation TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.pickupLocation):', err.message);
            }
        });
        
        // Add new columns to buses table
        db.run(`ALTER TABLE buses ADD COLUMN registrationStartDate TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (buses.registrationStartDate):', err.message);
            }
        });
        db.run(`ALTER TABLE buses ADD COLUMN registrationExpiredDate TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (buses.registrationExpiredDate):', err.message);
            }
        });
        db.run(`ALTER TABLE buses ADD COLUMN fcRenewalDate TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (buses.fcRenewalDate):', err.message);
            }
        });
        db.run(`ALTER TABLE buses ADD COLUMN busType TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (buses.busType):', err.message);
            }
        });
        
        // Add routeId column to students table
        db.run(`ALTER TABLE students ADD COLUMN routeId TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.routeId):', err.message);
            }
        });
        
        // Add busId column to routes table
        db.run(`ALTER TABLE routes ADD COLUMN busId TEXT`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (routes.busId):', err.message);
            }
        });
        
        // Add pickup/drop location columns to students table
        db.run(`ALTER TABLE students ADD COLUMN pickupLat REAL`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.pickupLat):', err.message);
            }
        });
        db.run(`ALTER TABLE students ADD COLUMN pickupLng REAL`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.pickupLng):', err.message);
            }
        });
        db.run(`ALTER TABLE students ADD COLUMN dropLat REAL`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.dropLat):', err.message);
            }
        });
        db.run(`ALTER TABLE students ADD COLUMN dropLng REAL`, (err) => {
            if (err && !err.message.includes('duplicate column')) {
                console.error('Migration error (students.dropLng):', err.message);
            }
        });
        
        console.log('Database migrations completed');
    });
}
migrateDatabase();

// Add a cache to store validated tokens
const tokenCache = new Map();

function authenticateToken(req, res, next)
{
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Malformed Authorization header' });

    const token = parts[1];

    // Check if the token is already cached
    if (tokenCache.has(token))
    {
        const cachedUser = tokenCache.get(token);
        // Check if the cached token is still valid
        if (cachedUser.exp > Date.now() / 1000)
        {
            req.user = cachedUser;
            return next();
        } else
        {
            tokenCache.delete(token); // Remove expired token from cache
        }
    }

    jwt.verify(token, JWT_SECRET, (err, user) =>
    {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        // Cache the token with its expiration time
        tokenCache.set(token, user);
        next();
    });
}

// Role-based permission check middleware
function requirePermission(permission) {
    return (req, res, next) => {
        const userRole = req.user?.userRole; // userRole from school_users.role
        if (req.user?.role === 'admin' || req.user?.role === 'school') return next(); // Admins and school owners bypass
        if (req.user?.role !== 'schoolUser') return res.status(403).json({ error: 'Unauthorized' });
        
        // Check schoolUser permissions
        if (permission === 'read') {
            return next(); // All schoolUser roles can read
        } else if (permission === 'write') {
            if (userRole === 'editor' || userRole === 'manager') return next();
            return res.status(403).json({ error: 'Write permission required (editor/manager role)' });
        } else if (permission === 'manage') {
            if (userRole === 'manager') return next();
            return res.status(403).json({ error: 'Manager permission required' });
        }
        return res.status(403).json({ error: 'Permission denied' });
    };
}

// Serve swagger UI
try
{
    const swaggerDoc = YAML.load(path.join(__dirname, '..', 'docs', 'swagger.yaml'));
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc, { explorer: true }));
    console.log('Swagger UI available at /api/docs');
} catch (e)
{
    console.error('Failed to load swagger.yaml:', e.message);
}

// ------------------ AUTH endpoints ------------------
app.post('/api/auth/login', async (req, res) =>
{
    try
    {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'username and password required' });
        const row = await getSql('SELECT * FROM admins WHERE username=?', [username]);
        if (!row) return res.status(401).json({ error: 'Invalid credentials' });
        const match = await bcrypt.compare(password, row.passwordHash);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: row.id, username: row.username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// Unified mobile login - auto-detects driver or parent by phone
app.post('/api/auth/mobile-login', async (req, res) => {
    try {
        const { phone } = req.body || {};
        if (!phone) return res.status(400).json({ error: 'phone required' });
        
        // Check if user is a driver first
        const driver = await getSql('SELECT * FROM drivers WHERE phone=?', [phone]);
        if (driver) {
            const token = jwt.sign({ id: driver.id, name: driver.name, role: 'driver', schoolId: driver.schoolId || null }, JWT_SECRET, { expiresIn: '24h' });
            return res.json({ 
                token, 
                role: 'driver',
                user: { id: driver.id, name: driver.name, phone: driver.phone, schoolId: driver.schoolId } 
            });
        }
        
        // If not a driver, check if user is a parent
        const parent = await getSql('SELECT * FROM parents WHERE phone=?', [phone]);
        if (parent) {
            const token = jwt.sign({ id: parent.id, name: parent.name, role: 'parent', schoolId: parent.schoolId || null }, JWT_SECRET, { expiresIn: '24h' });
            return res.json({ 
                token, 
                role: 'parent',
                user: { id: parent.id, name: parent.name, phone: parent.phone, schoolId: parent.schoolId } 
            });
        }
        
        // User not found in either table
        return res.status(404).json({ error: 'No account found with this phone number' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Driver login / auto-registration by phone
app.post('/api/auth/driver-login', async (req, res) => {
    try {
        const { phone } = req.body || {};
        if (!phone) return res.status(400).json({ error: 'phone required' });
        const row = await getSql('SELECT * FROM drivers WHERE phone=?', [phone]);
        if (!row) return res.status(404).json({ error: 'Driver not found with this phone number' });
        const token = jwt.sign({ id: row.id, name: row.name, role: 'driver', schoolId: row.schoolId || null }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, driver: { id: row.id, name: row.name, phone: row.phone, schoolId: row.schoolId } });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Parent login by phone
app.post('/api/auth/parent-login', async (req, res) => {
    try {
        const { phone } = req.body || {};
        if (!phone) return res.status(400).json({ error: 'phone required' });
        const row = await getSql('SELECT * FROM parents WHERE phone=?', [phone]);
        if (!row) return res.status(404).json({ error: 'Parent not found with this phone number' });
        const token = jwt.sign({ id: row.id, name: row.name, role: 'parent', schoolId: row.schoolId || null }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, parent: { id: row.id, name: row.name, phone: row.phone, schoolId: row.schoolId } });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// School login by username/password
app.post('/api/auth/school-login', async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'username and password required' });
        const row = await getSql('SELECT * FROM schools WHERE username=?', [username]);
        if (!row) return res.status(401).json({ error: 'Invalid credentials' });
        const match = await bcrypt.compare(password, row.passwordHash);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        
        // Check contract status and expiry
        const isActive = row.isActive !== 0; // Default to active if null
        const contractStartDate = row.contractStartDate;
        const contractEndDate = row.contractEndDate;
        const contractStatus = row.contractStatus || 'active';
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
        
        let accessAllowed = isActive;
        let message = null;
        let daysRemaining = null;
        
        // Check if contract dates are set
        if (!contractStartDate || !contractEndDate) {
            return res.status(403).json({ 
                error: 'Your contract has not been set up yet. Please contact the administrator to activate your account.',
                contractExpired: true,
                contractEndDate: null,
                contractStatus: 'pending'
            });
        }
        
        // Check contract expiry
        const endDate = new Date(contractEndDate);
        const currentDate = new Date(today);
        daysRemaining = Math.ceil((endDate - currentDate) / (1000 * 60 * 60 * 24));
        
        if (currentDate > endDate) {
            // Contract expired
            accessAllowed = false;
            message = 'Your contract has expired. Please contact the administrator for renewal.';
        } else if (daysRemaining <= 30 && daysRemaining > 0) {
            // Show renewal warning
            message = `Your contract will expire in ${daysRemaining} days. Please contact the administrator for renewal.`;
        }
        
        if (!accessAllowed) {
            return res.status(403).json({ 
                error: message || 'Your account has been deactivated. Please contact the administrator.',
                contractExpired: true,
                contractEndDate: contractEndDate,
                contractStatus: contractStatus
            });
        }
        
        const token = jwt.sign({ id: row.id, username: row.username, name: row.name, role: 'school' }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ 
            token, 
            school: { 
                id: row.id, 
                name: row.name, 
                username: row.username, 
                logo: row.logo, 
                photo: row.photo,
                contractStartDate: row.contractStartDate,
                contractEndDate: row.contractEndDate,
                contractStatus: row.contractStatus,
                daysRemaining: daysRemaining
            },
            message: message // Warning message if contract expiring soon
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// School user (sub-account) login
app.post('/api/auth/school-user-login', async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if(!username || !password) return res.status(400).json({ error: 'username and password required' });
        const user = await getSql('SELECT su.*, s.name as schoolName, s.logo as schoolLogo, s.photo as schoolPhoto FROM school_users su JOIN schools s ON su.schoolId=s.id WHERE su.username=? AND su.active=1', [username]);
        if(!user) return res.status(401).json({ error: 'Invalid credentials' });
        const match = await bcrypt.compare(password, user.passwordHash);
        if(!match) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, username: user.username, role: 'schoolUser', userRole: user.role, schoolId: user.schoolId, schoolName: user.schoolName }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, user: { id: user.id, username: user.username, role: user.role, schoolId: user.schoolId, schoolName: user.schoolName, logo: user.schoolLogo, photo: user.schoolPhoto } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ------------------ DRIVERS CRUD ------------------
app.get('/api/drivers', authenticateToken, async (req, res) =>
{
    try
    {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search } = req.query || {};
        let rows;
        if (schoolId) {
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE schoolId=? AND (name LIKE ? OR phone LIKE ?)', [schoolId, `%${search.trim()}%`, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE schoolId=?', [schoolId]);
            }
        } else {
            // Admin sees all
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE name LIKE ? OR phone LIKE ?', [`%${search.trim()}%`, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,phone,license,schoolId FROM drivers');
            }
        }
        res.json(rows);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/drivers/:id', authenticateToken, async (req, res) =>
{
    try
    {
        const row = await getSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE id=?', [req.params.id]);
        const schoolScope = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        if (schoolScope && row && row.schoolId && row.schoolId !== schoolScope) return res.status(404).json({ error: 'not found' });
        if (!row) return res.status(404).json({ error: 'not found' });
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/drivers/:id', authenticateToken, async (req, res) => {
    try {
        const row = await getSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE id=?', [req.params.id]);
        if (!row) return res.status(404).json({ error: 'Driver not found' });
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/drivers', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { name, phone, license } = req.body || {};
        if (!name) return res.status(400).json({ error: 'name is required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO drivers(id,name,phone,license,schoolId) VALUES(?,?,?,?,?)', [id, name, phone || null, license || null, schoolId]);
        const row = await getSql('SELECT id,name,phone,license,schoolId FROM drivers WHERE id=?', [id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/drivers/:id', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { name, phone, license } = req.body || {};
        await runSql('UPDATE drivers SET name=?,phone=?,license=? WHERE id=?', [name, phone, license, req.params.id]);
        const row = await getSql('SELECT id,name,phone,license FROM drivers WHERE id=?', [req.params.id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/drivers/:id', authenticateToken, requirePermission('manage'), async (req, res) =>
{
    try
    {
        await runSql('DELETE FROM drivers WHERE id=?', [req.params.id]);
        res.json({ deleted: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// Check if driver phone exists across all schools
app.get('/api/drivers/check-phone/:phone', authenticateToken, async (req, res) => {
    try {
        const phone = req.params.phone;
        const row = await getSql('SELECT id FROM drivers WHERE phone=?', [phone]);
        res.json({ exists: !!row });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ STUDENTS CRUD ------------------
app.get('/api/students', authenticateToken, async (req, res) => {
    try {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search, class: classFilter, bus: busFilter, route: routeFilter, parentId } = req.query || {};
        const params = [];
        let sql = 'SELECT id,name,cls,parentId,busId,routeId,schoolId,pickupLocation,pickupLat,pickupLng,dropLat,dropLng FROM students';
        const where = [];
        if (schoolId) { where.push('schoolId=?'); params.push(schoolId); }
        if (parentId && parentId.trim()) { where.push('parentId=?'); params.push(parentId.trim()); }
        if (search && search.trim()) { where.push('(name LIKE ? OR cls LIKE ?)'); params.push(`%${search.trim()}%`, `%${search.trim()}%`); }
        if (classFilter && classFilter.trim()) { where.push('cls=?'); params.push(classFilter.trim()); }
        if (busFilter && busFilter.trim()) { where.push('busId=?'); params.push(busFilter.trim()); }
        if (routeFilter && routeFilter.trim()) { where.push('routeId=?'); params.push(routeFilter.trim()); }
        if (where.length) sql += ' WHERE ' + where.join(' AND ');
        const rows = await allSql(sql, params);
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ CLASSES CRUD ------------------
app.get('/api/classes', authenticateToken, async (req, res) => {
    try {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.query.schoolId || null);
        const { includeInactive } = req.query || {};
        if (!schoolId && req.user?.role !== 'admin') return res.status(400).json({ error: 'schoolId required' });
        let sql = 'SELECT id,name,active,schoolId FROM classes WHERE schoolId=?';
        const params = [schoolId];
        if (!includeInactive) sql += ' AND active=1';
        const rows = await allSql(sql, params);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/classes', authenticateToken, async (req, res) => {
    try {
        const isViewer = req.user?.role === 'schoolUser' && req.user.userRole === 'viewer';
        if (isViewer) return res.status(403).json({ error: 'viewer cannot modify' });
        const { name, active } = req.body || {};
        if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        if (!schoolId) return res.status(400).json({ error: 'schoolId required' });
        const id = uuidv4();
        try {
            await runSql('INSERT INTO classes(id,name,active,schoolId) VALUES(?,?,?,?)', [id, name.trim(), active === 0 ? 0 : 1, schoolId]);
        } catch (err) {
            if (err && err.message.includes('UNIQUE')) return res.status(409).json({ error: 'class name exists' });
            throw err;
        }
        const row = await getSql('SELECT id,name,active,schoolId FROM classes WHERE id=?', [id]);
        res.json(row);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/classes/:id', authenticateToken, async (req, res) => {
    try {
        const isViewer = req.user?.role === 'schoolUser' && req.user.userRole === 'viewer';
        if (isViewer) return res.status(403).json({ error: 'viewer cannot modify' });
        const { name, active } = req.body || {};
        if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
        // ensure belongs to same school
        const existing = await getSql('SELECT id,schoolId FROM classes WHERE id=?', [req.params.id]);
        if (!existing) return res.status(404).json({ error: 'not found' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        if (schoolId && existing.schoolId !== schoolId && req.user?.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
        try {
            await runSql('UPDATE classes SET name=?, active=? WHERE id=?', [name.trim(), active === 0 ? 0 : 1, req.params.id]);
        } catch (err) {
            if (err && err.message.includes('UNIQUE')) return res.status(409).json({ error: 'class name exists' });
            throw err;
        }
        const row = await getSql('SELECT id,name,active,schoolId FROM classes WHERE id=?', [req.params.id]);
        res.json(row);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/students', authenticateToken, requirePermission('write'), async (req, res) => {
    try {
        const { name, cls, parentId, busId, routeId, pickupLocation, pickupLat, pickupLng, dropLat, dropLng } = req.body || {};
        if (!name) return res.status(400).json({ error: 'name is required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO students(id,name,cls,parentId,busId,routeId,schoolId,pickupLocation,pickupLat,pickupLng,dropLat,dropLng) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [id, name, cls || null, parentId || null, busId || null, routeId || null, schoolId, pickupLocation || null, pickupLat || null, pickupLng || null, dropLat || null, dropLng || null]);
        const row = await getSql('SELECT id,name,cls,parentId,busId,routeId,schoolId,pickupLocation,pickupLat,pickupLng,dropLat,dropLng FROM students WHERE id=?', [id]);
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/students/:id', authenticateToken, async (req, res) => {
    try {
        // Allow drivers to update only location fields, otherwise require write permission
        if (req.user?.role === 'driver') {
            // Drivers can only update location fields
            const { pickupLat, pickupLng, dropLat, dropLng } = req.body || {};
            await runSql('UPDATE students SET pickupLat=?,pickupLng=?,dropLat=?,dropLng=? WHERE id=?', [pickupLat, pickupLng, dropLat, dropLng, req.params.id]);
            const row = await getSql('SELECT id,name,cls,parentId,busId,routeId,schoolId,pickupLocation,pickupLat,pickupLng,dropLat,dropLng FROM students WHERE id=?', [req.params.id]);
            res.json(row);
        } else {
            // Other roles need write permission and can update all fields
            if (req.user?.role === 'schoolUser') {
                const userRole = req.user?.userRole;
                if (userRole !== 'editor' && userRole !== 'manager') {
                    return res.status(403).json({ error: 'Write permission required (editor/manager role)' });
                }
            } else if (req.user?.role !== 'admin' && req.user?.role !== 'school') {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            
            const { name, cls, parentId, busId, routeId, pickupLocation, pickupLat, pickupLng, dropLat, dropLng } = req.body || {};
            await runSql('UPDATE students SET name=?,cls=?,parentId=?,busId=?,routeId=?,pickupLocation=?,pickupLat=?,pickupLng=?,dropLat=?,dropLng=? WHERE id=?', [name, cls, parentId, busId, routeId, pickupLocation, pickupLat, pickupLng, dropLat, dropLng, req.params.id]);
            const row = await getSql('SELECT id,name,cls,parentId,busId,routeId,schoolId,pickupLocation,pickupLat,pickupLng,dropLat,dropLng FROM students WHERE id=?', [req.params.id]);
            res.json(row);
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/students/:id', authenticateToken, requirePermission('manage'), async (req, res) =>
{
    try
    {
        await runSql('DELETE FROM students WHERE id=?', [req.params.id]);
        res.json({ deleted: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ PARENTS CRUD ------------------
app.get('/api/parents', authenticateToken, async (req, res) =>
{
    try
    {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search } = req.query || {};
        let rows;
        if (schoolId) {
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,phone,schoolId FROM parents WHERE schoolId=? AND (name LIKE ? OR phone LIKE ?)', [schoolId, `%${search.trim()}%`, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,phone,schoolId FROM parents WHERE schoolId=?', [schoolId]);
            }
        } else {
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,phone,schoolId FROM parents WHERE name LIKE ? OR phone LIKE ?', [`%${search.trim()}%`, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,phone,schoolId FROM parents');
            }
        }
        res.json(rows);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/parents/:id', authenticateToken, async (req, res) => {
    try {
        const row = await getSql('SELECT id,name,phone,schoolId FROM parents WHERE id=?', [req.params.id]);
        if (!row) return res.status(404).json({ error: 'Parent not found' });
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/parents', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { name, phone } = req.body || {};
        if (!name) return res.status(400).json({ error: 'name is required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO parents(id,name,phone,schoolId) VALUES(?,?,?,?)', [id, name, phone || null, schoolId]);
        const row = await getSql('SELECT id,name,phone,schoolId FROM parents WHERE id=?', [id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});
// Check if parent phone exists across all schools
app.get('/api/parents/check-phone/:phone', authenticateToken, async (req, res) => {
    try {
        const phone = req.params.phone;
        const row = await getSql('SELECT id FROM parents WHERE phone=?', [phone]);
        res.json({ exists: !!row });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Fetch students belonging to a parent
app.get('/api/parents/:id/students', authenticateToken, async (req, res) => {
    try {
        const parentId = req.params.id;
        const schoolScope = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        let rows;
        if (schoolScope) {
            rows = await allSql('SELECT id,name,cls,parentId,busId,schoolId,pickupLocation FROM students WHERE parentId=? AND schoolId=?', [parentId, schoolScope]);
        } else {
            rows = await allSql('SELECT id,name,cls,parentId,busId,schoolId,pickupLocation FROM students WHERE parentId=?', [parentId]);
        }
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ BUSES CRUD + LOCATION ------------------
app.get('/api/buses', authenticateToken, async (req, res) => {
    try {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search } = req.query || {};
        let rows;
        if (schoolId) {
            if (search && search.trim()) {
                rows = await allSql('SELECT b.*, d.name as driverName FROM buses b LEFT JOIN drivers d ON b.driverId=d.id WHERE b.schoolId=? AND b.number LIKE ?', [schoolId, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT b.*, d.name as driverName FROM buses b LEFT JOIN drivers d ON b.driverId=d.id WHERE b.schoolId=?', [schoolId]);
            }
        } else {
            if (search && search.trim()) {
                rows = await allSql('SELECT b.*, d.name as driverName FROM buses b LEFT JOIN drivers d ON b.driverId=d.id WHERE b.number LIKE ?', [`%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT b.*, d.name as driverName FROM buses b LEFT JOIN drivers d ON b.driverId=d.id');
            }
        }
        res.json(rows.map(r => ({ id: r.id, number: r.number, driverId: r.driverId, driverName: r.driverName || null, routeId: r.routeId, schoolId: r.schoolId, started: !!r.started, location: r.lat !== null && r.lng !== null ? { lat: r.lat, lng: r.lng } : null, registrationStartDate: r.registrationStartDate || null, registrationExpiredDate: r.registrationExpiredDate || null, fcRenewalDate: r.fcRenewalDate || null, busType: r.busType || null })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/buses', authenticateToken, requirePermission('write'), async (req, res) => {
    try {
        const { number, driverId, routeId, started, registrationStartDate, registrationExpiredDate, fcRenewalDate, busType } = req.body || {};
        if (!number) return res.status(400).json({ error: 'number is required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO buses(id,number,driverId,routeId,started,schoolId,registrationStartDate,registrationExpiredDate,fcRenewalDate,busType) VALUES(?,?,?,?,?,?,?,?,?,?)', [id, number, driverId || null, routeId || null, started ? 1 : 0, schoolId, registrationStartDate || null, registrationExpiredDate || null, fcRenewalDate || null, busType || null]);
        const row = await getSql('SELECT * FROM buses WHERE id=?', [id]);
        res.json({ id: row.id, number: row.number, driverId: row.driverId, routeId: row.routeId, schoolId: row.schoolId, started: !!row.started, registrationStartDate: row.registrationStartDate, registrationExpiredDate: row.registrationExpiredDate, fcRenewalDate: row.fcRenewalDate, busType: row.busType });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/buses/:id', authenticateToken, requirePermission('write'), async (req, res) => {
    try {
        const { number, driverId, routeId, started, registrationStartDate, registrationExpiredDate, fcRenewalDate, busType } = req.body || {};
        await runSql('UPDATE buses SET number=?,driverId=?,routeId=?,started=?,registrationStartDate=?,registrationExpiredDate=?,fcRenewalDate=?,busType=? WHERE id=?', [number, driverId, routeId, started ? 1 : 0, registrationStartDate, registrationExpiredDate, fcRenewalDate, busType, req.params.id]);
        const row = await getSql('SELECT * FROM buses WHERE id=?', [req.params.id]);
        res.json({ id: row.id, number: row.number, driverId: row.driverId, routeId: row.routeId, schoolId: row.schoolId, started: !!row.started, registrationStartDate: row.registrationStartDate, registrationExpiredDate: row.registrationExpiredDate, fcRenewalDate: row.fcRenewalDate, busType: row.busType });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/buses/:id', authenticateToken, requirePermission('manage'), async (req, res) =>
{
    try
    {
        await runSql('DELETE FROM buses WHERE id=?', [req.params.id]);
        res.json({ deleted: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/buses/:id/location', authenticateToken, async (req, res) =>
{
    try
    {
        const id = req.params.id;
        const { lat, lng } = req.body || {};
        if (typeof lat !== 'number' || typeof lng !== 'number') return res.status(400).json({ error: 'lat and lng numeric required' });
        if (!req.user) return res.status(403).json({ error: 'Unauthorized' });
        if (req.user.role !== 'driver' && req.user.role !== 'admin') return res.status(403).json({ error: 'Only drivers/admins can update location' });
        await runSql('UPDATE buses SET lat=?, lng=? WHERE id=? OR number=?', [lat, lng, id, id]);
        const row = await getSql('SELECT * FROM buses WHERE id=? OR number=?', [id, id]);
        if (!row) return res.status(404).json({ error: 'Bus not found' });
        res.json({ id: row.id, number: row.number, location: row.lat !== null ? { lat: row.lat, lng: row.lng } : null });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ ROUTES CRUD ------------------
app.get('/api/routes', authenticateToken, async (req, res) =>
{
    try
    {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search } = req.query || {};
        let rows;
        if (schoolId) {
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,stops,busId,schoolId FROM routes WHERE schoolId=? AND name LIKE ?', [schoolId, `%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,stops,busId,schoolId FROM routes WHERE schoolId=?', [schoolId]);
            }
        } else {
            if (search && search.trim()) {
                rows = await allSql('SELECT id,name,stops,busId,schoolId FROM routes WHERE name LIKE ?', [`%${search.trim()}%`]);
            } else {
                rows = await allSql('SELECT id,name,stops,busId,schoolId FROM routes');
            }
        }
        const parsed = rows.map(r => ({ id: r.id, name: r.name, stops: r.stops ? JSON.parse(r.stops) : [], busId: r.busId || null, schoolId: r.schoolId }));
        res.json(parsed);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/routes', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { name, stops, busId } = req.body || {};
        if (!name) return res.status(400).json({ error: 'name is required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO routes(id,name,stops,busId,schoolId) VALUES(?,?,?,?,?)', [id, name, JSON.stringify(stops || []), busId || null, schoolId]);
        const row = await getSql('SELECT id,name,stops,busId,schoolId FROM routes WHERE id=?', [id]);
        res.json({ id: row.id, name: row.name, stops: row.stops ? JSON.parse(row.stops) : [], busId: row.busId || null, schoolId: row.schoolId });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/routes/:id', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { name, stops, busId } = req.body || {};
        await runSql('UPDATE routes SET name=?,stops=?,busId=? WHERE id=?', [name, JSON.stringify(stops || []), busId || null, req.params.id]);
        const row = await getSql('SELECT id,name,stops,busId,schoolId FROM routes WHERE id=?', [req.params.id]);
        res.json({ id: row.id, name: row.name, stops: row.stops ? JSON.parse(row.stops) : [], busId: row.busId || null, schoolId: row.schoolId });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/routes/:id', authenticateToken, requirePermission('manage'), async (req, res) =>
{
    try
    {
        await runSql('DELETE FROM routes WHERE id=?', [req.params.id]);
        res.json({ deleted: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ ASSIGNMENTS ------------------
app.post('/api/assignments', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { driverId, busId, routeId, startDate, endDate, trips } = req.body || {};
        if (!driverId || !busId) return res.status(400).json({ error: 'driverId and busId required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        const tripsJson = trips ? JSON.stringify(trips) : JSON.stringify(['morning','evening']);
        await runSql('INSERT INTO assignments(id,driverId,busId,routeId,schoolId,startDate,endDate,trips) VALUES(?,?,?,?,?,?,?,?)', [id, driverId, busId, routeId || null, schoolId, startDate || null, endDate || null, tripsJson]);
        const row = await getSql('SELECT * FROM assignments WHERE id=?', [id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/assignments', authenticateToken, async (req, res) =>
{
    try
    {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search, startDate, endDate, busId, driverId, routeId } = req.query || {};
        const params = [];
        let sql = 'SELECT * FROM assignments';
        const where = [];
        
        if (schoolId) { where.push('schoolId=?'); params.push(schoolId); }
        if (search && search.trim()) { 
            where.push('(driverId LIKE ? OR busId LIKE ? OR routeId LIKE ? OR startDate LIKE ? OR endDate LIKE ?)');
            params.push(`%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`);
        }
        if (startDate && startDate.trim()) { where.push('startDate>=?'); params.push(startDate.trim()); }
        if (endDate && endDate.trim()) { where.push('endDate<=?'); params.push(endDate.trim()); }
        if (busId && busId.trim()) { where.push('busId=?'); params.push(busId.trim()); }
        if (driverId && driverId.trim()) { where.push('driverId=?'); params.push(driverId.trim()); }
        if (routeId && routeId.trim()) { where.push('routeId=?'); params.push(routeId.trim()); }
        
        if (where.length) sql += ' WHERE ' + where.join(' AND ');
        sql += ' ORDER BY startDate DESC, endDate DESC';
        const rows = await allSql(sql, params);
        res.json(rows);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/assignments/:id', authenticateToken, requirePermission('write'), async (req, res) =>
{
    try
    {
        const { driverId, busId, routeId, startDate, endDate, trips } = req.body || {};
        const tripsJson = trips ? JSON.stringify(trips) : null;
        await runSql('UPDATE assignments SET driverId=?,busId=?,routeId=?,startDate=?,endDate=?,trips=? WHERE id=?', [driverId, busId, routeId, startDate, endDate, tripsJson, req.params.id]);
        const row = await getSql('SELECT * FROM assignments WHERE id=?', [req.params.id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/assignments/:id', authenticateToken, requirePermission('manage'), async (req, res) =>
{
    try
    {
        await runSql('DELETE FROM assignments WHERE id=?', [req.params.id]);
        res.json({ deleted: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ ATTENDANCE ------------------
app.post('/api/attendance', authenticateToken, async (req, res) =>
{
    try
    {
        // Allow drivers to mark attendance, otherwise require write permission
        if (req.user?.role === 'driver') {
            // Drivers can mark attendance - no additional permission check
        } else if (req.user?.role === 'schoolUser') {
            const userRole = req.user?.userRole;
            if (userRole !== 'editor' && userRole !== 'manager') {
                return res.status(403).json({ error: 'Write permission required (editor/manager role)' });
            }
        } else if (req.user?.role !== 'admin' && req.user?.role !== 'school') {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const { studentId, busId, timestamp, status } = req.body || {};
        if (!studentId) return res.status(400).json({ error: 'studentId required' });
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : req.body.schoolId || null);
        const id = uuidv4();
        await runSql('INSERT INTO attendance(id,studentId,busId,timestamp,status,schoolId) VALUES(?,?,?,?,?,?)', [id, studentId, busId || null, timestamp || Date.now(), status || 'present', schoolId]);
        const row = await getSql('SELECT * FROM attendance WHERE id=?', [id]);
        res.json(row);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/attendance', authenticateToken, async (req, res) =>
{
    try
    {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        const { search, dateFrom, dateTo, studentId, status } = req.query || {};
        
        const params = [];
        let sql = 'SELECT * FROM attendance';
        const where = [];
        
        if (schoolId) {
            where.push('schoolId=?');
            params.push(schoolId);
        }
        
        if (search && search.trim()) {
            where.push('(studentId LIKE ? OR status LIKE ?)');
            params.push(`%${search.trim()}%`, `%${search.trim()}%`);
        }
        
        if (studentId && studentId.trim()) {
            where.push('studentId=?');
            params.push(studentId.trim());
        }
        
        if (status && status.trim()) {
            where.push('status=?');
            params.push(status.trim());
        }
        
        // Date filtering - convert timestamp to date for comparison
        if (dateFrom && dateFrom.trim()) {
            const fromTimestamp = new Date(dateFrom.trim()).setHours(0, 0, 0, 0);
            where.push('timestamp>=?');
            params.push(fromTimestamp);
        }
        
        if (dateTo && dateTo.trim()) {
            const toTimestamp = new Date(dateTo.trim()).setHours(23, 59, 59, 999);
            where.push('timestamp<=?');
            params.push(toTimestamp);
        }
        
        if (where.length) {
            sql += ' WHERE ' + where.join(' AND ');
        }
        
        sql += ' ORDER BY timestamp DESC';
        
        const rows = await allSql(sql, params);
        res.json(rows);
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ SCHOOLS ------------------
// Public minimal schools list for login dropdown (no auth required)
app.get('/api/public/schools', async (req, res) => {
    try {
        const { search } = req.query || {};
        let rows;
        if (search && search.trim()) {
            rows = await allSql('SELECT id,name,username,logo FROM schools WHERE name LIKE ? ORDER BY name ASC', [ `%${search.trim()}%` ]);
        } else {
            rows = await allSql('SELECT id,name,username,logo FROM schools ORDER BY name ASC');
        }
        res.json(rows.map(r => ({ id: r.id, name: r.name, username: r.username, logo: r.logo })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Public single school profile (minimal but with branding fields)
app.get('/api/public/schools/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const row = await getSql('SELECT id,name,address,city,state,phone,mobile,logo,photo,headerColorFrom,headerColorTo,sidebarColorFrom,sidebarColorTo FROM schools WHERE id=?', [id]);
        if(!row) return res.status(404).json({ error: 'School not found' });
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
app.get('/api/schools', authenticateToken, async (req, res) => {
    try {
        // Admin: full paginated list with search
        if (req.user?.role === 'admin') {
            const { search, page, limit } = req.query;
            const pageNum = parseInt(page) || 1;
            const pageLimit = parseInt(limit) || 10;
            const offset = (pageNum - 1) * pageLimit;
            let base = 'FROM schools';
            let where = '';
            let params = [];
            if (search) {
                where = ' WHERE name LIKE ? OR city LIKE ? OR state LIKE ?';
                params = [`%${search}%`, `%${search}%`, `%${search}%`];
            }
            const countRow = await getSql(`SELECT COUNT(*) as total ${base}${where}`, params);
            const rows = await allSql(`SELECT id,name,address,city,state,county,phone,mobile,username,logo,photo,headerColorFrom,headerColorTo,sidebarColorFrom,sidebarColorTo,contractStartDate,contractEndDate,contractStatus,isActive ${base}${where} ORDER BY rowid DESC LIMIT ? OFFSET ?`, [...params, pageLimit, offset]);
            return res.json({ data: rows, total: countRow.total || 0, page: pageNum, limit: pageLimit });
        }
        // School admin: only its own record
        if (req.user?.role === 'school') {
            const row = await getSql('SELECT id,name,address,city,state,county,phone,mobile,username,logo,photo,headerColorFrom,headerColorTo,sidebarColorFrom,sidebarColorTo,contractStartDate,contractEndDate,contractStatus,isActive FROM schools WHERE id=?', [req.user.id]);
            return res.json({ data: row ? [row] : [], total: row ? 1 : 0 });
        }
        // School sub-user / driver / parent: only their school's record (if schoolId present)
        if (['schoolUser','driver','parent'].includes(req.user?.role)) {
            if (!req.user.schoolId) return res.json({ data: [], total: 0 });
            const row = await getSql('SELECT id,name,address,city,state,county,phone,mobile,username,logo,photo,headerColorFrom,headerColorTo,sidebarColorFrom,sidebarColorTo,contractStartDate,contractEndDate,contractStatus,isActive FROM schools WHERE id=?', [req.user.schoolId]);
            return res.json({ data: row ? [row] : [], total: row ? 1 : 0 });
        }
        return res.status(403).json({ error: 'Unauthorized role' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Upload school logo (500KB max) — store in DB, return serving URL
app.post('/api/upload/logo', authenticateToken, (req, res) => {
    const logoUpload = multer({
        storage: memoryStorage,
        limits: { fileSize: 500 * 1024 },
        fileFilter: (req, file, cb) => {
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            if (allowedTypes.includes(file.mimetype)) cb(null, true); else cb(new Error('Only image files are allowed'));
        }
    }).single('logo');

    logoUpload(req, res, async (err) => {
        try {
            if (err) {
                if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Logo file size must be less than 500KB' });
                return res.status(400).json({ error: err.message });
            }
            if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
            const schoolId = req.user?.role === 'school' ? req.user.id : (req.user?.role === 'admin' ? (req.body?.schoolId || null) : req.user?.schoolId);
            if (!schoolId) return res.status(400).json({ error: 'schoolId scope required' });
            // Store as base64 data URL in DB for portability
            const mime = req.file.mimetype;
            const dataUrl = `data:${mime};base64,${req.file.buffer.toString('base64')}`;
            await runSql('UPDATE schools SET logo=? WHERE id=?', [dataUrl, schoolId]);
            return res.json({ path: `/api/schools/${schoolId}/logo`, size: req.file.size });
        } catch (e) {
            return res.status(500).json({ error: e.message });
        }
    });
});

// Upload school banner (1MB max) — store in DB, return serving URL
app.post('/api/upload/banner', authenticateToken, (req, res) => {
    const bannerUpload = multer({
        storage: memoryStorage,
        limits: { fileSize: 1 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            if (allowedTypes.includes(file.mimetype)) cb(null, true); else cb(new Error('Only image files are allowed'));
        }
    }).single('banner');

    bannerUpload(req, res, async (err) => {
        try {
            if (err) {
                if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Banner file size must be less than 1MB' });
                return res.status(400).json({ error: err.message });
            }
            if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
            const schoolId = req.user?.role === 'school' ? req.user.id : (req.user?.role === 'admin' ? (req.body?.schoolId || null) : req.user?.schoolId);
            if (!schoolId) return res.status(400).json({ error: 'schoolId scope required' });
            const mime = req.file.mimetype;
            const dataUrl = `data:${mime};base64,${req.file.buffer.toString('base64')}`;
            await runSql('UPDATE schools SET photo=? WHERE id=?', [dataUrl, schoolId]);
            return res.json({ path: `/api/schools/${schoolId}/banner`, size: req.file.size });
        } catch (e) {
            return res.status(500).json({ error: e.message });
        }
    });
});

// Serve logo/banner from DB (data URL stored)
app.get('/api/schools/:id/logo', async (req, res) => {
    try {
        const row = await getSql('SELECT logo FROM schools WHERE id=?', [req.params.id]);
        if (!row || !row.logo) return res.status(404).send('Not found');
        const match = /^data:(.+);base64,(.+)$/.exec(row.logo);
        if (!match) return res.status(200).send(row.logo);
        const mime = match[1]; const b64 = match[2];
        const buf = Buffer.from(b64, 'base64');
        res.setHeader('Content-Type', mime);
        res.setHeader('Content-Length', buf.length);
        return res.end(buf);
    } catch (e) { return res.status(500).json({ error: e.message }); }
});
app.get('/api/schools/:id/banner', async (req, res) => {
    try {
        const row = await getSql('SELECT photo FROM schools WHERE id=?', [req.params.id]);
        if (!row || !row.photo) return res.status(404).send('Not found');
        const match = /^data:(.+);base64,(.+)$/.exec(row.photo);
        if (!match) return res.status(200).send(row.photo);
        const mime = match[1]; const b64 = match[2];
        const buf = Buffer.from(b64, 'base64');
        res.setHeader('Content-Type', mime);
        res.setHeader('Content-Length', buf.length);
        return res.end(buf);
    } catch (e) { return res.status(500).json({ error: e.message }); }
});

app.post('/api/schools', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role!=='admin') return res.status(403).json({ error: 'admin only' });
        const { name, address, city, state, county, phone, mobile, username, password, logo, photo } = req.body || {};
        if (!name || !username || !password) return res.status(400).json({ error: 'name, username, password required' });
        const exist = await getSql('SELECT id FROM schools WHERE username=?', [username]);
        if(exist) return res.status(409).json({ error: 'username exists' });
        const id = uuidv4();
        const hash = await new Promise((resolve,reject)=>{ require('bcrypt').hash(password,10,(err,h)=> err?reject(err):resolve(h)); });
        await runSql('INSERT INTO schools(id,name,address,city,state,county,phone,mobile,username,passwordHash,logo,photo) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [id,name,address||null,city||null,state||null,county||null,phone||null,mobile||null,username,hash,logo||null,photo||null]);
        const row = await getSql('SELECT id,name,address,city,state,county,phone,mobile,username,logo,photo FROM schools WHERE id=?',[id]);
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Update school profile (excluding password)
app.put('/api/schools/:id', authenticateToken, async (req, res) => {
    try {
        // Admin can edit any school, school admin can edit only their own
        if(req.user?.role === 'admin') {
            // Admin logic
        } else if(req.user?.role === 'school') {
            // School admin can only edit their own profile
            if(req.user.id !== req.params.id) {
                return res.status(403).json({ error: 'Cannot edit other school profiles' });
            }
        } else {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const { name, address, city, state, county, phone, mobile, logo, photo, headerColorFrom, headerColorTo, sidebarColorFrom, sidebarColorTo, contractStartDate, contractEndDate, contractStatus, isActive } = req.body || {};
        if (!name || !name.trim()) return res.status(400).json({ error: 'School name is required' });
        
        // Build dynamic SQL based on who is updating
        let sql, params;
        if(req.user?.role === 'admin') {
            // Admin can update everything including contract fields
            sql = 'UPDATE schools SET name=?,address=?,city=?,state=?,county=?,phone=?,mobile=?,logo=?,photo=?,headerColorFrom=?,headerColorTo=?,sidebarColorFrom=?,sidebarColorTo=?,contractStartDate=?,contractEndDate=?,contractStatus=?,isActive=? WHERE id=?';
            params = [name, address, city, state, county, phone, mobile, logo||null, photo||null, headerColorFrom||null, headerColorTo||null, sidebarColorFrom||null, sidebarColorTo||null, contractStartDate||null, contractEndDate||null, contractStatus||null, isActive !== undefined ? isActive : null, req.params.id];
        } else {
            // School admin cannot update contract fields
            sql = 'UPDATE schools SET name=?,address=?,city=?,state=?,county=?,phone=?,mobile=?,logo=?,photo=?,headerColorFrom=?,headerColorTo=?,sidebarColorFrom=?,sidebarColorTo=? WHERE id=?';
            params = [name, address, city, state, county, phone, mobile, logo||null, photo||null, headerColorFrom||null, headerColorTo||null, sidebarColorFrom||null, sidebarColorTo||null, req.params.id];
        }
        
        await runSql(sql, params);
        const row = await getSql('SELECT id,name,address,city,state,county,phone,mobile,username,logo,photo,headerColorFrom,headerColorTo,sidebarColorFrom,sidebarColorTo,contractStartDate,contractEndDate,contractStatus,isActive FROM schools WHERE id=?',[req.params.id]);
        if(!row) return res.status(404).json({ error: 'not found' });
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Reset school password
app.post('/api/schools/:id/reset-password', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role!=='admin') return res.status(403).json({ error: 'admin only' });
        const { password } = req.body || {};
        if(!password || password.length < 6) return res.status(400).json({ error: 'password min 6 chars' });
        const hash = await new Promise((resolve,reject)=>{ require('bcrypt').hash(password,10,(err,h)=> err?reject(err):resolve(h)); });
        await runSql('UPDATE schools SET passwordHash=? WHERE id=?',[hash, req.params.id]);
        res.json({ reset: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Update school contract details (admin only)
app.post('/api/schools/:id/contract', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role!=='admin') return res.status(403).json({ error: 'admin only' });
        const { contractStartDate, contractEndDate, contractStatus, isActive } = req.body || {};
        
        await runSql('UPDATE schools SET contractStartDate=?, contractEndDate=?, contractStatus=?, isActive=? WHERE id=?', 
            [contractStartDate||null, contractEndDate||null, contractStatus||'active', isActive !== undefined ? (isActive ? 1 : 0) : 1, req.params.id]);
        
        const row = await getSql('SELECT id,name,contractStartDate,contractEndDate,contractStatus,isActive FROM schools WHERE id=?', [req.params.id]);
        res.json(row);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ NOTIFICATIONS ------------------
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST || 'localhost', port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 25, secure: false, tls: { rejectUnauthorized: false } });
// WhatsApp notifications via Twilio (optional)
let twilioClient = null;
try {
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    if (sid && token) {
        twilioClient = require('twilio')(sid, token);
        console.log('Twilio client initialized for WhatsApp notifications');
    }
} catch (e) {
    console.warn('Twilio not configured:', e.message);
}

async function sendWhatsApp(toPhone, message) {
    try {
        if (!twilioClient) return false;
        const fromWhatsApp = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886'; // Default Twilio sandbox number
        const toWhatsApp = `whatsapp:${toPhone.startsWith('+') ? toPhone : '+' + toPhone}`;
        await twilioClient.messages.create({ from: fromWhatsApp, to: toWhatsApp, body: message });
        return true;
    } catch (e) {
        console.warn('WhatsApp send failed:', e.message);
        return false;
    }
}
app.post('/api/notifications/email', authenticateToken, async (req, res) =>
{
    try
    {
        const { to, subject, text } = req.body || {};
        if (!to || !subject) return res.status(400).json({ error: 'to and subject required' });
        await transporter.sendMail({ from: process.env.EMAIL_FROM || 'no-reply@example.com', to, subject, text });
        res.json({ sent: true });
    } catch (e)
    {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ DASHBOARD/HEALTH ------------------
app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
    try {
        const schoolId = req.user?.role === 'school' ? req.user.id : (['schoolUser','driver','parent'].includes(req.user?.role) ? req.user.schoolId : null);
        if (req.user?.role !== 'admin' && !schoolId) {
            return res.status(403).json({ error: 'No school scope available for this user' });
        }
        const buses = schoolId ? await getSql('SELECT COUNT(*) as c FROM buses WHERE schoolId=?', [schoolId]) : await getSql('SELECT COUNT(*) as c FROM buses');
        const drivers = schoolId ? await getSql('SELECT COUNT(*) as c FROM drivers WHERE schoolId=?', [schoolId]) : await getSql('SELECT COUNT(*) as c FROM drivers');
        const students = schoolId ? await getSql('SELECT COUNT(*) as c FROM students WHERE schoolId=?', [schoolId]) : await getSql('SELECT COUNT(*) as c FROM students');
        const parents = schoolId ? await getSql('SELECT COUNT(*) as c FROM parents WHERE schoolId=?', [schoolId]) : await getSql('SELECT COUNT(*) as c FROM parents');
        const routes = schoolId ? await getSql('SELECT COUNT(*) as c FROM routes WHERE schoolId=?', [schoolId]) : await getSql('SELECT COUNT(*) as c FROM routes');
        const schools = req.user?.role === 'admin' ? await getSql('SELECT COUNT(*) as c FROM schools') : null;
        res.json({ buses: buses.c || 0, drivers: drivers.c || 0, students: students.c || 0, parents: parents.c || 0, routes: routes.c || 0, schools: schools?.c || 0 });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ------------------ SCHOOL USERS MANAGEMENT ------------------
// All endpoints restricted to main school admin (role 'school')
app.get('/api/school-users', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'school') return res.status(403).json({ error: 'school admin only' });
        const rows = await allSql('SELECT id,username,role,active,createdAt FROM school_users WHERE schoolId=? ORDER BY createdAt DESC', [req.user.id]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school-users', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'school') return res.status(403).json({ error: 'school admin only' });
        const { username, password, role } = req.body || {};
        if(!username || !password || password.length < 6) return res.status(400).json({ error: 'username & password (>=6) required' });
        const exist = await getSql('SELECT id FROM school_users WHERE schoolId=? AND username=?', [req.user.id, username]);
        if(exist) return res.status(409).json({ error: 'username exists' });
        const id = uuidv4(); const hash = await bcrypt.hash(password,10); const now = Date.now();
        await runSql('INSERT INTO school_users(id,schoolId,username,passwordHash,role,active,createdAt) VALUES(?,?,?,?,?,?,?)',[id, req.user.id, username, hash, role||'editor',1, now]);
        const row = await getSql('SELECT id,username,role,active,createdAt FROM school_users WHERE id=?',[id]);
        res.json(row);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/school-users/:id/reset-password', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'school') return res.status(403).json({ error: 'school admin only' });
        const { password } = req.body || {}; if(!password || password.length<6) return res.status(400).json({ error: 'password min 6' });
        const hash = await bcrypt.hash(password,10);
        await runSql('UPDATE school_users SET passwordHash=? WHERE id=? AND schoolId=?',[hash, req.params.id, req.user.id]);
        res.json({ reset:true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/school-users/:id', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'school') return res.status(403).json({ error: 'school admin only' });
        const { role, active } = req.body || {};
        await runSql('UPDATE school_users SET role=COALESCE(?,role), active=COALESCE(?,active) WHERE id=? AND schoolId=?',[role, typeof active==='number'?active:null, req.params.id, req.user.id]);
        const row = await getSql('SELECT id,username,role,active,createdAt FROM school_users WHERE id=? AND schoolId=?',[req.params.id, req.user.id]);
        if(!row) return res.status(404).json({ error:'not found' });
        res.json(row);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/school-users/:id', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'school') return res.status(403).json({ error: 'school admin only' });
        await runSql('DELETE FROM school_users WHERE id=? AND schoolId=?',[req.params.id, req.user.id]);
        res.json({ deleted:true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get school details/dashboard by ID (for admin viewing specific school)
app.get('/api/schools/:id/dashboard', authenticateToken, async (req, res) => {
    try {
        if(req.user?.role !== 'admin') return res.status(403).json({ error: 'admin only' });
        const schoolId = req.params.id;
        const school = await getSql('SELECT id,name,address,city,state,logo,photo FROM schools WHERE id=?', [schoolId]);
        if(!school) return res.status(404).json({ error: 'school not found' });
        const buses = await getSql('SELECT COUNT(*) as c FROM buses WHERE schoolId=?', [schoolId]);
        const drivers = await getSql('SELECT COUNT(*) as c FROM drivers WHERE schoolId=?', [schoolId]);
        const students = await getSql('SELECT COUNT(*) as c FROM students WHERE schoolId=?', [schoolId]);
        const parents = await getSql('SELECT COUNT(*) as c FROM parents WHERE schoolId=?', [schoolId]);
        const routes = await getSql('SELECT COUNT(*) as c FROM routes WHERE schoolId=?', [schoolId]);
        res.json({ school, stats: { buses: buses.c || 0, drivers: drivers.c || 0, students: students.c || 0, parents: parents.c || 0, routes: routes.c || 0 } });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/health', (req, res) => res.json({ ok: true, now: Date.now() }));

// ------------------ TRIPS (in-memory minimal) ------------------
const activeTrips = new Map(); // key: busId, value: { tripId, busId, driverId, schoolId, direction: 'morning'|'evening', startedAt, lastPingAt, status: 'running'|'stopped' }
// Minimal in-memory stop state per trip
const tripStops = new Map(); // key: busId, value: { currentStopIndex: number, arrivedAt?: number, dropped: Record<string, number>, approached: Set<number> }

app.post('/api/trips/start', authenticateToken, async (req, res) => {
    try {
        if (req.user?.role !== 'driver' && req.user?.role !== 'admin') return res.status(403).json({ error: 'driver/admin only' });
        const { busId, direction } = req.body || {};
        if (!busId) return res.status(400).json({ error: 'busId required' });
        const dir = direction === 'evening' ? 'evening' : 'morning';
        const tripId = uuidv4();
        const startedAt = Date.now();
        activeTrips.set(busId, { tripId, busId, driverId: req.user.id, schoolId: req.user.schoolId || null, direction: dir, startedAt, lastPingAt: startedAt, status: 'running' });
        tripStops.set(busId, { currentStopIndex: 0, dropped: {}, approached: new Set() });
        await runSql('UPDATE buses SET started=? WHERE id=?', [1, busId]);
        await runSql('INSERT INTO trips(id,busId,driverId,schoolId,direction,startedAt,status) VALUES(?,?,?,?,?,?,?)', [tripId, busId, req.user.id, req.user.schoolId || null, dir, startedAt, 'running']);
        await runSql('INSERT INTO trip_events(id,tripId,busId,type,data,createdAt) VALUES(?,?,?,?,?,?)', [uuidv4(), tripId, busId, 'trip_started', JSON.stringify({ direction: dir }), Date.now()]);
        // Notify parents (WhatsApp) of students on this bus
        try {
            const parentsOnBus = await allSql('SELECT DISTINCT p.phone as phone, s.name as studentName FROM students s JOIN parents p ON s.parentId=p.id WHERE s.busId=? AND p.phone IS NOT NULL', [busId]);
            const school = await getSql('SELECT name FROM schools WHERE id=?', [req.user.schoolId || null]);
            const schoolName = school?.name || 'School';
            const dirWord = dir === 'evening' ? 'Evening' : 'Morning';
            for (const p of parentsOnBus) {
                const msg = `🚌 ${schoolName}: ${dirWord} trip started for ${p.studentName}.`;
                await sendWhatsApp(p.phone, msg);
            }
        } catch (e) { console.warn('Trip start notify failed:', e.message); }
        res.json(activeTrips.get(busId));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/trips/stop', authenticateToken, async (req, res) => {
    try {
        if (req.user?.role !== 'driver' && req.user?.role !== 'admin') return res.status(403).json({ error: 'driver/admin only' });
        const { busId } = req.body || {};
        if (!busId) return res.status(400).json({ error: 'busId required' });
        const trip = activeTrips.get(busId);
        if (!trip) return res.status(404).json({ error: 'no active trip' });
        trip.status = 'stopped';
        trip.stoppedAt = Date.now();
        activeTrips.delete(busId);
        tripStops.delete(busId);
        await runSql('UPDATE buses SET started=? WHERE id=?', [0, busId]);
        await runSql('UPDATE trips SET stoppedAt=?, status=? WHERE id=?', [trip.stoppedAt, 'stopped', trip.tripId]);
        await runSql('INSERT INTO trip_events(id,tripId,busId,type,data,createdAt) VALUES(?,?,?,?,?,?)', [uuidv4(), trip.tripId, busId, 'trip_stopped', JSON.stringify({}), Date.now()]);
        res.json({ stopped: true, tripId: trip.tripId, stoppedAt: trip.stoppedAt });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update location and touch trip last ping if active
app.post('/api/trips/:busId/location', authenticateToken, async (req, res) => {
    try {
        const { busId } = req.params;
        const { lat, lng } = req.body || {};
        if (typeof lat !== 'number' || typeof lng !== 'number') return res.status(400).json({ error: 'lat/lng numeric required' });
        await runSql('UPDATE buses SET lat=?, lng=? WHERE id=? OR number=?', [lat, lng, busId, busId]);
        const trip = activeTrips.get(busId);
        if (trip) {
            trip.lastPingAt = Date.now();
            await runSql('INSERT INTO trip_locations(id,tripId,busId,lat,lng,pingAt) VALUES(?,?,?,?,?,?)', [uuidv4(), trip.tripId, busId, lat, lng, Date.now()]);

            // Geofenced approaching notification to next stop
            try {
                const state = tripStops.get(busId) || { currentStopIndex: 0, dropped: {}, approached: new Set() };
                const routeRow = await getSql('SELECT stops FROM routes WHERE id=?', [trip.routeId || null]);
                if (routeRow && routeRow.stops) {
                    const stops = JSON.parse(routeRow.stops);
                    const nextIdx = Math.max(0, state.currentStopIndex || 0);
                    const nextStop = stops[nextIdx];
                    if (nextStop && typeof nextStop.lat === 'number' && typeof nextStop.lng === 'number') {
                        const toRad = (v) => v * Math.PI / 180;
                        const R = 6371000;
                        const dLat = toRad(nextStop.lat - lat);
                        const dLng = toRad(nextStop.lng - lng);
                        const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat)) * Math.cos(toRad(nextStop.lat)) * Math.sin(dLng/2)**2;
                        const distance = 2 * R * Math.asin(Math.sqrt(a));
                        const threshold = 400; // meters to consider "approaching"
                        if (distance <= threshold && !state.approached.has(nextIdx)) {
                            state.approached.add(nextIdx);
                            await runSql('INSERT INTO trip_events(id,tripId,busId,type,data,createdAt) VALUES(?,?,?,?,?,?)', [uuidv4(), trip.tripId, busId, 'approach_stop', JSON.stringify({ index: nextIdx, distance }), Date.now()]);
                            // Notify parents near this stop (same matching as arrive)
                            try {
                                const candidates = await allSql('SELECT s.id as studentId, s.name as studentName, s.pickupLat as lat, s.pickupLng as lng, p.phone as phone FROM students s JOIN parents p ON s.parentId=p.id WHERE s.busId=? AND p.phone IS NOT NULL', [busId]);
                                const within = [];
                                for (const c of candidates) {
                                    if (typeof c.lat === 'number' && typeof c.lng === 'number') {
                                        const dLat2 = toRad(nextStop.lat - c.lat);
                                        const dLng2 = toRad(nextStop.lng - c.lng);
                                        const a2 = Math.sin(dLat2/2)**2 + Math.cos(toRad(c.lat)) * Math.cos(toRad(nextStop.lat)) * Math.sin(dLng2/2)**2;
                                        const d2 = 2 * R * Math.asin(Math.sqrt(a2));
                                        if (d2 <= 500) within.push(c); // 500m notify radius for approaching
                                    }
                                }
                                for (const p of within) {
                                    await sendWhatsApp(p.phone, `⏳ Bus is approaching your stop for ${p.studentName}. ETA ~${Math.max(1, Math.round(distance / 250))} min.`);
                                }
                            } catch (e) { console.warn('Approach stop notify failed:', e.message); }
                            tripStops.set(busId, state);
                        }
                    }
                }
            } catch (e) { console.warn('Approaching check failed:', e.message); }
        }
        res.json({ ok: true, busId, lat, lng, running: !!trip });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Arrive at current stop (advance index optional)
app.post('/api/trips/:busId/arrive-stop', authenticateToken, async (req, res) => {
    try {
        if (req.user?.role !== 'driver' && req.user?.role !== 'admin') return res.status(403).json({ error: 'driver/admin only' });
        const { busId } = req.params;
        const { advance } = req.body || {};
        const trip = activeTrips.get(busId);
        if (!trip) return res.status(404).json({ error: 'no active trip' });
        const state = tripStops.get(busId) || { currentStopIndex: 0, dropped: {} };
        state.arrivedAt = Date.now();
        await runSql('INSERT INTO trip_events(id,tripId,busId,type,data,createdAt) VALUES(?,?,?,?,?,?)', [uuidv4(), trip.tripId, busId, 'arrive_stop', JSON.stringify({ currentStopIndex: state.currentStopIndex, advance: !!advance }), Date.now()]);
        // Notify only parents whose students are tied to this stop (nearest-stop matching)
        try {
            const route = await getSql('SELECT stops FROM routes WHERE id=?', [trip.routeId || null]);
            let stopCoord = null;
            if (route && route.stops) {
                try {
                    const stops = JSON.parse(route.stops);
                    const idx = Math.max(0, state.currentStopIndex || 0);
                    const s = stops[idx];
                    if (s && typeof s.lat === 'number' && typeof s.lng === 'number') {
                        stopCoord = { lat: s.lat, lng: s.lng };
                    }
                } catch {}
            }
            if (stopCoord) {
                // Find students on this bus whose pickup location is within ~100m of stop
                const candidates = await allSql('SELECT s.id as studentId, s.name as studentName, s.pickupLat as lat, s.pickupLng as lng, p.phone as phone FROM students s JOIN parents p ON s.parentId=p.id WHERE s.busId=? AND p.phone IS NOT NULL', [busId]);
                const within = [];
                for (const c of candidates) {
                    if (typeof c.lat === 'number' && typeof c.lng === 'number') {
                        // Haversine distance in meters
                        const toRad = (v) => v * Math.PI / 180;
                        const R = 6371000;
                        const dLat = toRad(stopCoord.lat - c.lat);
                        const dLng = toRad(stopCoord.lng - c.lng);
                        const a = Math.sin(dLat/2)**2 + Math.cos(toRad(c.lat)) * Math.cos(toRad(stopCoord.lat)) * Math.sin(dLng/2)**2;
                        const d = 2 * R * Math.asin(Math.sqrt(a));
                        if (d <= 120) within.push(c); // 120m radius buffer
                    }
                }
                for (const p of within) {
                    await sendWhatsApp(p.phone, `📍 Bus is arriving at your stop for ${p.studentName}.`);
                }
            } else {
                // Fallback broadcast when stop coordinate unavailable
                const parentsOnBus = await allSql('SELECT DISTINCT p.phone as phone FROM students s JOIN parents p ON s.parentId=p.id WHERE s.busId=? AND p.phone IS NOT NULL', [busId]);
                for (const p of parentsOnBus) {
                    await sendWhatsApp(p.phone, '🅿️ Bus has arrived at the stop.');
                }
            }
        } catch (e) { console.warn('Arrive stop notify failed:', e.message); }
        if (advance === true) state.currentStopIndex += 1;
        tripStops.set(busId, state);
        res.json({ ok: true, busId, currentStopIndex: state.currentStopIndex, arrivedAt: state.arrivedAt });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Mark a student dropped at current stop
app.post('/api/trips/:busId/drop-student', authenticateToken, async (req, res) => {
    try {
        if (req.user?.role !== 'driver' && req.user?.role !== 'admin') return res.status(403).json({ error: 'driver/admin only' });
        const { busId } = req.params;
        const { studentId } = req.body || {};
        if (!studentId) return res.status(400).json({ error: 'studentId required' });
        const trip = activeTrips.get(busId);
        if (!trip) return res.status(404).json({ error: 'no active trip' });
        const state = tripStops.get(busId) || { currentStopIndex: 0, dropped: {} };
        state.dropped[studentId] = Date.now();
        await runSql('INSERT INTO trip_events(id,tripId,busId,type,data,createdAt) VALUES(?,?,?,?,?,?)', [uuidv4(), trip.tripId, busId, 'drop_student', JSON.stringify({ studentId }), Date.now()]);
        // Notify this student's parent
        try {
            const p = await getSql('SELECT parents.phone as phone, students.name as studentName FROM students JOIN parents ON students.parentId=parents.id WHERE students.id=?', [studentId]);
            if (p?.phone) {
                await sendWhatsApp(p.phone, `✅ ${p.studentName} has been dropped.`);
            }
        } catch (e) { console.warn('Drop student notify failed:', e.message); }
        tripStops.set(busId, state);
        res.json({ ok: true, busId, studentId, droppedAt: state.dropped[studentId], currentStopIndex: state.currentStopIndex });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Public-ish live status for parents (scope restricted by schoolId when available)
app.get('/api/public/bus/:busId/live', async (req, res) => {
    try {
        const busId = req.params.busId;
        const bus = await getSql('SELECT id,number,driverId,routeId,schoolId,lat,lng,started FROM buses WHERE id=? OR number=?', [busId, busId]);
        if (!bus) return res.status(404).json({ error: 'bus not found' });
        const trip = activeTrips.get(bus.id);
        const stopState = tripStops.get(bus.id) || null;
        res.json({
            id: bus.id,
            number: bus.number,
            schoolId: bus.schoolId,
            running: !!trip || !!bus.started,
            location: (bus.lat != null && bus.lng != null) ? { lat: bus.lat, lng: bus.lng } : null,
            lastPingAt: trip?.lastPingAt || null,
            direction: trip?.direction || null,
            startedAt: trip?.startedAt || null,
            tripId: trip?.tripId || null,
            currentStopIndex: stopState?.currentStopIndex ?? null,
            routeId: bus.routeId || null,
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Trip history endpoints (admin/school scope)
app.get('/api/trips', authenticateToken, async (req, res) => {
    try {
        const { busId, status } = req.query || {};
        let sql = 'SELECT * FROM trips';
        const where = []; const params = [];
        if (busId && busId.trim()) { where.push('busId=?'); params.push(busId.trim()); }
        if (status && status.trim()) { where.push('status=?'); params.push(status.trim()); }
        if (where.length) sql += ' WHERE ' + where.join(' AND ');
        sql += ' ORDER BY startedAt DESC';
        const rows = await allSql(sql, params);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/trips/:id/locations', authenticateToken, async (req, res) => {
    try {
        const rows = await allSql('SELECT lat,lng,pingAt FROM trip_locations WHERE tripId=? ORDER BY pingAt ASC', [req.params.id]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/trips/:id/events', authenticateToken, async (req, res) => {
    try {
        const rows = await allSql('SELECT type,data,createdAt FROM trip_events WHERE tripId=? ORDER BY createdAt ASC', [req.params.id]);
        res.json(rows.map(r => ({ type: r.type, data: r.data ? JSON.parse(r.data) : null, createdAt: r.createdAt })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
