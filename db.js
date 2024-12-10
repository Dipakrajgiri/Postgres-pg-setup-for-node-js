const { Pool } = require('pg');
require('dotenv').config();

const client = new Pool({
  connectionString: process.env.DATABASE_URL, 
});

module.exports = client;
