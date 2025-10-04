const mysql = require('mysql2');
const bcrypt = require('bcrypt');
require('dotenv').config();

const db = mysql.createConnection({
    host: 'localhost',
    port: 3307,
    user: 'root',
    password: '',
    database: 'luct_reporting_system'
});

async function migratePasswords() {
    try {
        console.log('🔄 Starting password migration...');
        
        // Migrate users table
        const users = await new Promise((resolve, reject) => {
            db.query('SELECT id, password FROM users WHERE password IS NOT NULL', (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        console.log(`📊 Found ${users.length} users to migrate`);
        
        for (const user of users) {
            // Check if password is already hashed (bcrypt hashes start with $2)
            if (!user.password.startsWith('$2')) {
                const hashedPassword = await bcrypt.hash(user.password, 10);
                
                await new Promise((resolve, reject) => {
                    db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
                
                console.log(`✅ Migrated user ID: ${user.id}`);
            }
        }

        // Migrate students table
        const students = await new Promise((resolve, reject) => {
            db.query('SELECT id, password FROM students WHERE password IS NOT NULL', (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });

        console.log(`📊 Found ${students.length} students to migrate`);
        
        for (const student of students) {
            if (!student.password.startsWith('$2')) {
                const hashedPassword = await bcrypt.hash(student.password, 10);
                
                await new Promise((resolve, reject) => {
                    db.query('UPDATE students SET password = ? WHERE id = ?', [hashedPassword, student.id], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
                
                console.log(`✅ Migrated student ID: ${student.student_id}`);
            }
        }

        console.log('🎉 Password migration completed successfully!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Migration error:', error);
        process.exit(1);
    }
}

migratePasswords();