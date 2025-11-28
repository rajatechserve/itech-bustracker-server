const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

module.exports = function initDb(db){
  db.serialize(()=>{
    db.run(`CREATE TABLE IF NOT EXISTS admins(id TEXT PRIMARY KEY, username TEXT UNIQUE, passwordHash TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS drivers(id TEXT PRIMARY KEY, name TEXT, phone TEXT, license TEXT, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS students(id TEXT PRIMARY KEY, name TEXT, cls TEXT, parentId TEXT, busId TEXT, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS parents(id TEXT PRIMARY KEY, name TEXT, phone TEXT, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS buses(id TEXT PRIMARY KEY, number TEXT, driverId TEXT, routeId TEXT, started INTEGER DEFAULT 0, lat REAL, lng REAL, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS routes(id TEXT PRIMARY KEY, name TEXT, stops TEXT, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS attendance(id TEXT PRIMARY KEY, studentId TEXT, busId TEXT, timestamp INTEGER, status TEXT, schoolId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS assignments(id TEXT PRIMARY KEY, driverId TEXT, busId TEXT, routeId TEXT, schoolId TEXT, startDate TEXT, endDate TEXT)`);
    // Classes (per school, unique name)
    db.run(`CREATE TABLE IF NOT EXISTS classes(id TEXT PRIMARY KEY, name TEXT, active INTEGER DEFAULT 1, schoolId TEXT)`);
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_classes_unique ON classes(schoolId, name)');
    
    // Extended schools schema with all columns including contract management
    db.run(`CREATE TABLE IF NOT EXISTS schools(
      id TEXT PRIMARY KEY, 
      name TEXT, 
      address TEXT, 
      city TEXT, 
      state TEXT, 
      county TEXT, 
      phone TEXT, 
      mobile TEXT, 
      username TEXT UNIQUE, 
      passwordHash TEXT, 
      logo TEXT, 
      photo TEXT,
      headerColorFrom TEXT,
      headerColorTo TEXT,
      sidebarColorFrom TEXT,
      sidebarColorTo TEXT,
      contractStartDate TEXT,
      contractEndDate TEXT,
      contractStatus TEXT,
      isActive INTEGER DEFAULT 1
    )`);
    
    // School users (sub-accounts managed by school admin)
    db.run(`CREATE TABLE IF NOT EXISTS school_users(id TEXT PRIMARY KEY, schoolId TEXT, username TEXT, passwordHash TEXT, role TEXT, active INTEGER DEFAULT 1, createdAt INTEGER)`);
    db.all("PRAGMA table_info(school_users)", (err, rows)=>{
      if(err||!rows) return;
      const have=(c)=>rows.some(r=>r.name===c);
      if(!have('role')) db.run('ALTER TABLE school_users ADD COLUMN role TEXT');
      if(!have('active')) db.run('ALTER TABLE school_users ADD COLUMN active INTEGER DEFAULT 1');
      if(!have('createdAt')) db.run('ALTER TABLE school_users ADD COLUMN createdAt INTEGER');
    });
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_school_users_unique ON school_users(schoolId, username)');
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_school_users_username_global ON school_users(username)');
    
    // Only add missing columns for legacy databases (backward compatibility)
    db.all("PRAGMA table_info(students)", (err, rows)=>{
      if(!err && rows && !rows.some(c=>c.name==='parentId')){
        db.run("ALTER TABLE students ADD COLUMN parentId TEXT");
      }
      if(!err && rows && !rows.some(c=>c.name==='busId')){
        db.run("ALTER TABLE students ADD COLUMN busId TEXT");
      }
      if(!err && rows && !rows.some(c=>c.name==='schoolId')){
        db.run("ALTER TABLE students ADD COLUMN schoolId TEXT");
      }
    });
    
    db.all("PRAGMA table_info(buses)", (err, rows)=>{
      if(!err && rows && !rows.some(c=>c.name==='routeId')){
        db.run("ALTER TABLE buses ADD COLUMN routeId TEXT");
      }
      if(!err && rows && !rows.some(c=>c.name==='schoolId')){
        db.run("ALTER TABLE buses ADD COLUMN schoolId TEXT");
      }
    });
    
    db.all("PRAGMA table_info(assignments)", (err, rows)=>{
      if(!err && rows && !rows.some(c=>c.name==='startDate')){
        db.run("ALTER TABLE assignments ADD COLUMN startDate TEXT");
      }
      if(!err && rows && !rows.some(c=>c.name==='endDate')){
        db.run("ALTER TABLE assignments ADD COLUMN endDate TEXT");
      }
    });
    
    // Add missing columns to legacy schools table (for existing databases only)
    db.all("PRAGMA table_info(schools)", (err, rows)=>{
      if(err||!rows) return;
      const have = (c)=> rows.some(r=>r.name===c);
      const toAdd = [
        ['city','TEXT'],['state','TEXT'],['county','TEXT'],['phone','TEXT'],['mobile','TEXT'],
        ['username','TEXT'],['passwordHash','TEXT'],['logo','TEXT'],['photo','TEXT'],
        ['headerColorFrom','TEXT'],['headerColorTo','TEXT'],['sidebarColorFrom','TEXT'],['sidebarColorTo','TEXT'],
        ['contractStartDate','TEXT'],['contractEndDate','TEXT'],['contractStatus','TEXT'],['isActive','INTEGER']
      ].filter(([c])=>!have(c));
      
      // Add any missing columns
      toAdd.forEach(([c,t])=>{ 
        db.run(`ALTER TABLE schools ADD COLUMN ${c} ${t}`, (err) => {
          if (err) console.error(`Error adding column ${c}:`, err.message);
        }); 
      });
      
      // Set default values for existing schools
      setTimeout(() => {
        db.run("UPDATE schools SET isActive = 1 WHERE isActive IS NULL");
        db.run("UPDATE schools SET contractStatus = 'active' WHERE contractStatus IS NULL");
      }, 100);
      
      // Ensure username uniqueness
      if(have('username')) db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_username ON schools(username)');
    });
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_drivers_phone ON drivers(phone)');
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_parents_phone ON parents(phone)');
    db.get("SELECT id FROM admins WHERE username='admin'", (err,row)=>{
      if(!row){
        bcrypt.hash('admin123',10,(e,h)=>{ if(!e) db.run(`INSERT INTO admins (id, username, passwordHash) VALUES (?,?,?)`, [uuidv4(),'admin',h]); });
      }
    });
  });
};
