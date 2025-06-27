// config/dbConfig.js
require('dotenv').config(); // Ensure .env is loaded

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: process.env.DB_ENCRYPT === 'true', // For Azure SQL
        trustServerCertificate: false // Change to true for local dev / self-signed certs
    },
    port: parseInt(process.env.DB_PORT || "1433")
};

module.exports = config;