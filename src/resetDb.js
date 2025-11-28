// Reset the SQLite database by deleting the file and recreating schema.
// Usage: node src/resetDb.js  (or via npm run reset-db once script added)

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const initDb = require('./dbInit');

const DB_FILE = path.join(__dirname, '..', 'app.db');

(async function main(){
  try {
    if (fs.existsSync(DB_FILE)) {
      fs.unlinkSync(DB_FILE);
      console.log('Deleted existing database file:', DB_FILE);
    } else {
      console.log('No existing database file found, creating new one.');
    }
    const db = new sqlite3.Database(DB_FILE);
    initDb(db);
    // Wait a brief moment for serialize() ops to complete then close.
    setTimeout(()=>{
      db.close();
      console.log('Recreated schema and closed DB. Reset complete.');
    }, 300);
  } catch (e) {
    console.error('Reset failed:', e.message);
    process.exit(1);
  }
})();
